/*
MIT License

Copyright (c) 2017 Peer Dampmann

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bio.h>
#include <sys/buf.h>
#include <sys/conf.h>
#include <sys/devicestat.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/limits.h>
#include <sys/linker.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/nadioctl.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/sx.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/rwlock.h>
#include <sys/sbuf.h>
#include <sys/sched.h>
#include <sys/sf_buf.h>
#include <sys/sysctl.h>


#include <sys/socket.h>
#include <sys/socketvar.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <geom/geom.h>
#include <geom/geom_int.h>

#include <machine/bus.h>


#define NAD_MODVERSION 1
#define NAD_SHUTDOWN 0x10000
#define NAD_EXITING 0x20000
#define BS128K 131072

static MALLOC_DEFINE(M_NAD, "nad_disk", "Network attached disk");

static int nad_debug;

SYSCTL_INT(_debug, OID_AUTO, naddebug, CTLFLAG_RW, &nad_debug, 0,
        "Enable nad debug messages");

/*
    To use this module you need to run nadserver in order to offer
    a network attached disk to nadservice. nadserver is running remotely
    on freebsd, linux or windows. nadservice is running locally. This module
    will connect to nadservice for each attached network disk and nadservice
    (running in userlandi) will communicate via rpc with nadserver.
    Each disk has a designated port configured and reported by nadservice and
    nadserver. nadconfig attaches and sets up the pre-configured network 
    attached disk and makes it available as a normal device.

    g_nad_init is the entry point when geom_nad.ko is loaded.
    It creates a geom class called nad and sets up a device /dev/nadctl.
    Using ioctl structures you create network attached disk devices.
    These devices are nad providers. g_nad_start, g_nad_access and
    g_nad_dumpconf get called when io goes to one of these devices.

    g_nad_fini is the exit point when geom_nad.ko is unloaded.
    It destroys the control device /dev/nadctl.

    nadctlioctl is bound to the control device /dev/nadctl
    and forwards the job to be done to xnadctlioctl. It acquires a config
    lock before it forwards the nad_cmd request.

    NADIOCATTACH

    This command will create a network attached disk (a new geom_nad provider).
    It uses nad_unit, nad_sectorsize and nad_mediasize to create a new virtual
    disk bound to /dev/nad{nad_unit}.

    It calls nadnew. nadnew allocates and initializes a nad_softc structure.
    It creates a thread nadgiothread. This thread deals with bio structs put
    into bio_queue for this device by g_nad_start and calls naddoio to handle
    the data. Furthermore it creates nad_network_thread. This thread sets up the
    socket and connection to nadservice by calling nad_connect_socket and 
    nad_configure_socket. nad_configure_socket  configures the socket options 
    and sets up upcalls for sends and receives in case the low water marks are 
    reached to wakeup threads waiting to send or receive bio buffers. Then this 
    thread creates the new provider and device on success.
    
    It would be awesome to use mmap in nadservice to avoid the local network
    stuff, unfortunately I don't know how yet and I want to see it working.
    It is a nice exercise to do network programming in kernel space and gives
    some interesting insights useful for userland network programming.
*/

static g_init_t g_nad_init;
static g_fini_t g_nad_fini;
static g_start_t g_nad_start;
static g_access_t g_nad_access;
static void g_nad_dumpconf(struct sbuf *sb, const char *indent, 
        struct g_geom *gp, struct g_consumer *cp __unused, struct g_provider *pp); 

static struct sx nad_sx;
static struct cdev *status_dev = 0;
static d_ioctl_t nadctlioctl;

//just for testing - will be removed as soon as networking works
struct vdisk_buffer {
    char *buffer;
    struct mtx m;
};

struct nad_wire_msg {
    off_t offset;
    uint64_t length;
    int rc;
};

static struct cdevsw nadctl_cdevsw = {
    .d_version = D_VERSION,
    .d_ioctl = nadctlioctl,
    .d_name = NAD_NAME,
};

struct g_class g_nad_class = {
    .name = "NAD",
    .version = G_VERSION,
    .init = g_nad_init,
    .fini = g_nad_fini,
    .start = g_nad_start,
    .access = g_nad_access,
    .dumpconf = g_nad_dumpconf,
};

DECLARE_GEOM_CLASS(g_nad_class, g_nad);

static LIST_HEAD(, nad_softc) nad_softc_list = LIST_HEAD_INITIALIZER(nad_softc_list);

struct nad_softc {
    int unit;
    LIST_ENTRY(nad_softc) list;
    struct bio_queue_head bio_queue;
    struct mtx queue_mtx;
    struct mtx stat_mtx;
    struct cdev *dev;
    off_t mediasize;
    unsigned sectorsize;
    unsigned flags;
    char name[64];
    struct proc *gio_proc;
    struct proc *net_proc;
    struct g_geom *gp;
    struct g_provider *pp;
    struct socket *nad_so;
    int (*start)(struct nad_softc *sc, struct bio *bp);
    struct devstat *devstat;
    struct vdisk_buffer *vdisk;
    int port;
    int opencount;
    int is_connected;
    int is_sending;
    int is_receiving;
    int can_rx;
    int can_sx;
    int shutdown;
    int disconnect;
};

static int nad_rupcall(struct socket *so, void *arg, int waitflag);
static int nad_supcall(struct socket *so, void *arg, int waitflag);
static void nad_rx_thread(void *arg);
static void nad_sx_thread(void *arg);
static struct nad_softc* nadfind(int unit);
static struct nad_softc* nadnew(int unit, off_t mediasize, int port, int *errp); 
static void nadnewprovider(struct nad_softc *sc); 
static int naddestroy(struct nad_softc *sc, struct thread *td); 
static void nadgiothread(void *arg); 
static int naddoio(struct nad_softc *sc, struct bio *bp); 
static void nad_network_thread(void *arg);
static int nad_connect_socket(struct nad_softc *sc);
static void nad_close_socket(struct nad_softc *sc);

/* If the low water mark is reached wakeup threads waiting to receive data */
static int 
nad_rupcall(struct socket *so, void *arg, int waitflag) {
    struct nad_softc *sc = arg;
    wakeup(&sc->can_rx);
    return(SU_OK);
}

/* If the low water mark is reached wakeup threads waiting to send data */
static int 
nad_supcall(struct socket *so, void *arg, int waitflag) {
    struct nad_softc *sc = arg;
    wakeup(&sc->can_sx);
    return(SU_OK);
}

static void 
nad_close_socket(struct nad_softc *sc) {
    if(sc->is_connected || sc->disconnect) {
        sc->is_connected = 0;
        sc->flags |= NAD_SHUTDOWN;
        //do some cleanup here
    }

    struct socket *so = sc->nad_so;
    if(so != NULL) {
        SOCKBUF_LOCK(&so->so_rcv);
		soupcall_clear(so, SO_RCV);
		while (sc->is_receiving) {
			wakeup(&sc->is_receiving);
			msleep(&sc->is_receiving, SOCKBUF_MTX(&so->so_rcv),
			    0, "nad exit", 0);
		}
		SOCKBUF_UNLOCK(&so->so_rcv);
		SOCKBUF_LOCK(&so->so_snd);
		soupcall_clear(so, SO_SND);
		SOCKBUF_UNLOCK(&so->so_snd);
		sc->nad_so = NULL;
		soclose(so);       
        sc->shutdown = 1;
    }
}

static void
nad_network_thread(void *arg) {
    struct nad_softc *sc = arg;

    /*XXX Something is missing here to avoid busy spinning */
    while(1) {
        if(sc->shutdown)
            break;

        if(sc->disconnect) {
            nad_close_socket(sc);
            sc->disconnect = 0; 
        }

        if(sc->nad_so == NULL) {
            nad_connect_socket(sc);
        }

        if(sc->nad_so != NULL) {
            if(sc->is_connected == 0 && sc->nad_so->so_error == 0 &&
                    (sc->nad_so->so_state & SS_ISCONNECTING) == 0) {
                sc->is_connected = 1;
                nadnewprovider(sc);
            }
        }
    }
}

static int 
naddoio(struct nad_softc *sc, struct bio *bp) {
    int error = 0;
    caddr_t buf = bp->bio_data;
    u_int berr = 0;

	switch (bp->bio_cmd) {
        case BIO_READ:
            if((bp->bio_offset+bp->bio_bcount) < sc->mediasize) {
                mtx_lock(&sc->vdisk->m);
                memcpy(buf, sc->vdisk->buffer+bp->bio_offset, bp->bio_bcount);
                mtx_unlock(&sc->vdisk->m);
            } else {
                berr = EIO;
                goto errout;
            }
            break;
        case BIO_WRITE:
            if((bp->bio_offset+bp->bio_bcount) <= sc->mediasize) {
                mtx_lock(&sc->vdisk->m);
                memcpy(sc->vdisk->buffer+bp->bio_offset, buf, bp->bio_bcount);
                mtx_unlock(&sc->vdisk->m);
            } else {
                berr = EIO;
                goto errout;
            }
            break;
	case BIO_DELETE:
        if((bp->bio_offset+bp->bio_bcount) <= sc->mediasize) {
            mtx_lock(&sc->vdisk->m);
            memset(sc->vdisk->buffer+bp->bio_offset, 0, bp->bio_bcount);
            mtx_unlock(&sc->vdisk->m);
        } else {
            berr = EIO;
            goto errout;
        }

		break;
	default:
		return (EOPNOTSUPP);
	}

 errout:                                                                              
    if (berr != 0) {                                                           
        bp->bio_flags |= BIO_ERROR;                                            
        bp->bio_error = berr;                                                  
    }

    bp->bio_resid = 0;
    return(error);
}

static void 
nadgiothread(void *arg) {
    struct nad_softc *sc;
    struct bio *bp;
    int error = 0;
    sc = arg;
    thread_lock(curthread);
    sched_prio(curthread, PRIBIO);
    thread_unlock(curthread);

    for(;;) {
        mtx_lock(&sc->queue_mtx);
        if(sc->flags & NAD_SHUTDOWN) {
            sc->flags |= NAD_EXITING;
            mtx_unlock(&sc->queue_mtx);
            kproc_exit(0);
        }

        bp = bioq_takefirst(&sc->bio_queue);
        if(!bp) {
            //PDROP - lock is not re-locked on return of msleep
            msleep(sc, &sc->queue_mtx, PRIBIO | PDROP, "nadwait", 0);
            continue;
        }

        mtx_unlock(&sc->queue_mtx);

        if (bp->bio_cmd == BIO_GETATTR) {
            error = EOPNOTSUPP;
        } else {
            //call naddoio
            error = sc->start(sc, bp);
        }

        if(error != -1) {
            bp->bio_completed = bp->bio_length;
            if ((bp->bio_cmd == BIO_READ) || (bp->bio_cmd == BIO_WRITE)) {
                devstat_end_transaction_bio(sc->devstat, bp);
            }

            g_io_deliver(bp, error);
        }
    }
}

static struct nad_softc* 
nadnew(int unit, off_t mediasize, int port, int *errp) {
    struct nad_softc *sc;
    int error;

    *errp = 0;

    if(unit < 0 || unit > 999) {
        *errp = EBUSY;
        return(NULL);
    }

    sc = (struct nad_softc *)malloc(sizeof *sc, M_NAD, M_WAITOK | M_ZERO);
    sc->vdisk = (struct vdisk_buffer*)malloc(sizeof(struct vdisk_buffer), M_NAD, M_WAITOK | M_ZERO);
    sc->vdisk->buffer = malloc(mediasize*sizeof(char), M_NAD, M_WAITOK | M_ZERO);
    mtx_init(&sc->vdisk->m, "nad vdisk buffer", NULL, MTX_DEF);
    bioq_init(&sc->bio_queue);
    mtx_init(&sc->queue_mtx, "nad bio queue", NULL, MTX_DEF);
    mtx_init(&sc->stat_mtx, "nad stat", NULL, MTX_DEF);
    sc->unit = unit;
    sc->port = port;
    sc->opencount = 0;
    sc->mediasize = mediasize;
    sc->is_sending = 0;
    sc->is_receiving = 0;
    sc->shutdown = 0;
    sc->disconnect = 0;
    sc->is_connected = 0;
    if(unit < 10) {
        sprintf(sc->name, "nad00%d", unit);
    } else if(unit < 100) {
        sprintf(sc->name, "nad0%d", unit);
    } else {
        sprintf(sc->name, "nad%d", unit);
    }
    LIST_INSERT_HEAD(&nad_softc_list, sc, list);
    sc->start = naddoio;
    error = kproc_create(nadgiothread, sc, &sc->gio_proc, 0, 0, "%s", sc->name);
    if(error == 0) {
        return(sc);
    }

    LIST_REMOVE(sc, list);
    mtx_destroy(&sc->vdisk->m);
    mtx_destroy(&sc->stat_mtx);
    mtx_destroy(&sc->queue_mtx);
    free(sc->vdisk->buffer, M_NAD);
    free(sc->vdisk, M_NAD);
    free(sc, M_NAD);
    *errp = error;
    return(NULL);
}

static struct nad_softc*
nadfind(int unit) {
    struct nad_softc *sc = NULL;
    LIST_FOREACH(sc, &nad_softc_list, list) {
        if(sc->unit == unit) {
            break;
        }
    }

    return(sc);
}

static void 
nadnewprovider(struct nad_softc *sc) {
    struct g_geom *gp;
    struct g_provider *gpp;

    g_topology_lock();
    if(sc->unit < 10) {
        gp = g_new_geomf(&g_nad_class, "nad00%d", sc->unit);
        gpp = g_new_providerf(gp, "nad00%d", sc->unit);
    } else if(sc->unit < 100) {
        gp = g_new_geomf(&g_nad_class, "nad0%d", sc->unit);
        gpp = g_new_providerf(gp, "nad0%d", sc->unit);
    } else {
        gp = g_new_geomf(&g_nad_class, "nad%d", sc->unit);
        gpp = g_new_providerf(gp, "nad%d", sc->unit);
    }
    gp->softc = sc;
    gpp->flags |= G_PF_DIRECT_SEND | G_PF_DIRECT_RECEIVE;
    gpp->mediasize = sc->mediasize;
    gpp->sectorsize = sc->sectorsize;
    sc->gp = gp;
    sc->pp = gpp;
    g_error_provider(gpp, 0);
    g_topology_unlock();
    sc->devstat = devstat_new_entry("nad", sc->unit, sc->sectorsize,
            DEVSTAT_ALL_SUPPORTED, DEVSTAT_TYPE_DIRECT, DEVSTAT_PRIORITY_MAX);
}

static int 
naddestroy(struct nad_softc *sc, struct thread *td) {
    if(sc->gp) {
        sc->gp->softc = NULL;
        g_topology_lock();
        g_wither_geom(sc->gp, ENXIO);
        g_topology_unlock();
        sc->gp = NULL;
        sc->pp = NULL;
    }

    if(sc->devstat) {
        devstat_remove_entry(sc->devstat);
        sc->devstat = NULL;
    }

    mtx_lock(&sc->queue_mtx);
    sc->flags |= NAD_SHUTDOWN;
    wakeup(sc);
    while(!(sc->flags & NAD_EXITING)) {
        msleep(sc->gio_proc, &sc->queue_mtx, PRIBIO, "naddestroy", hz/10);
    }

    mtx_unlock(&sc->queue_mtx);
    mtx_destroy(&sc->vdisk->m);
    mtx_destroy(&sc->stat_mtx);
    mtx_destroy(&sc->queue_mtx);
    LIST_REMOVE(sc, list);
    free(sc->vdisk->buffer, M_NAD);
    free(sc->vdisk, M_NAD);
    free(sc, M_NAD);
    return(0);
}

static int 
xnadctlioctl(struct cdev *dev, u_long cmd, caddr_t addr, int flags, struct thread *td) {
    struct nad_ioctl *nadio;
    struct nad_softc *sc;
    int error = 0;
    int i = 0;

    nadio = (struct nad_ioctl*)addr;
    switch(cmd) {
        case NADIOCATTACH:
            if((nadio->nad_sectorsize <= 0) || (nadio->nad_sectorsize > BS128K)) {
                nadio->nad_sectorsize = DEV_BSIZE;
            } 

            if(nadio->nad_mediasize < nadio->nad_sectorsize)
                return(EINVAL);

            i = nadio->nad_mediasize % nadio->nad_sectorsize;
            nadio->nad_mediasize -= i;
            sc = nadnew(nadio->nad_unit, nadio->nad_mediasize, nadio->nad_port, &error);
            if(sc == NULL)
                return(error);

            sc->sectorsize = nadio->nad_sectorsize;
            error = kproc_create(nad_network_thread, sc, &sc->net_proc, 
                    0, 0, "%s", sc->name);
            if (error != 0) {
                printf("error creating CTL NAD connection thread for nad%d!\n",
                        sc->unit);
                naddestroy(sc, td);
                return(error);
            }
            //call on successful connect!
            return(0);
        case NADIOCDETACH:
            sc = nadfind(nadio->nad_unit);
            if(sc == NULL)
                return(ENOENT);
            if(sc->opencount != 0)
                return(EBUSY);
            //XXX change this, not corrct yet
            return(naddestroy(sc, td));
        default:
            return(ENOIOCTL);
    }
}

static int
nadctlioctl(struct cdev *dev, u_long cmd, caddr_t addr, int flags, struct thread *td) {
    int error = 0;
    sx_xlock(&nad_sx);
    error = xnadctlioctl(dev, cmd, addr, flags, td);
    sx_xunlock(&nad_sx);
    return(error);
}

static void
nad_rx_thread(void *arg) {
    struct nad_softc *sc = arg;
    struct socket *so = sc->nad_so;
    struct nad_wire_msg ctl_hdr;
	struct uio uio;
	struct iovec iov;
    int next, error, flags;

    bzero(&ctl_hdr, sizeof(ctl_hdr));

    while(1) {
        if(ctl_hdr.length > 0) {
            next = ctl_hdr.length;
        } else {
            next = sizeof(ctl_hdr);
        }

        SOCKBUF_LOCK(&so->so_rcv);
        /*
           XXX should be if and msleep on can_rx otherwise 
           need to distinguish between ctl_hdr and data
         */
		while (sbavail(&so->so_rcv) < next || sc->disconnect) {
			if (sc->is_connected == 0 || sc->disconnect ||
			    so->so_error ||
			    (so->so_rcv.sb_state & SBS_CANTRCVMORE)) {
				goto errout;
			}
			so->so_rcv.sb_lowat = next;
			msleep(&sc->can_rx, SOCKBUF_MTX(&so->so_rcv),
			    0, "-", 0);
		}
        SOCKBUF_UNLOCK(&so->so_rcv);

		if (ctl_hdr.length == 0) {
			iov.iov_base = &ctl_hdr;
			iov.iov_len = sizeof(ctl_hdr);
			uio.uio_iov = &iov;
			uio.uio_iovcnt = 1;
			uio.uio_rw = UIO_READ;
			uio.uio_segflg = UIO_SYSSPACE;
			uio.uio_td = curthread;
			uio.uio_resid = sizeof(ctl_hdr);
			flags = MSG_DONTWAIT;
			error = soreceive(so, NULL, &uio, NULL,
			    NULL, &flags);
			if (error != 0) {
				printf("%s: ctl_hdr receive error %d\n",
				    __func__, error);
				SOCKBUF_LOCK(&so->so_rcv);
				goto errout;
			}
		} else {
            /*
			ctl_nad_evt(sc, ctl_hdr.channel,
			    CTL_NAD_EVT_MSG_RECV, ctl_hdr.length);
			ctl_hdr.length = 0;
            */
		}
    }

errout:
	sc->can_rx = 0;
	wakeup(&sc->can_rx);
	SOCKBUF_UNLOCK(&so->so_rcv);
	//ctl_ha_conn_wake(softc);
	kthread_exit();
}

static void
nad_sx_thread(void *arg) {

}

//add options to ioctl
static void 
nad_setup_socket(struct nad_softc *sc) {
    struct sockopt opt;
    struct socket *so = sc->nad_so;
    int err, val;

    val = 2 * sc->sectorsize;
    err = soreserve(so, val, val);
    if(err) {
       printf("%s: soreserve failed %d\n", __func__, err);
    } 

	SOCKBUF_LOCK(&so->so_rcv);
	so->so_rcv.sb_lowat = sizeof(struct nad_wire_msg);
	soupcall_set(so, SO_RCV, nad_rupcall, sc);
	SOCKBUF_UNLOCK(&so->so_rcv);
	SOCKBUF_LOCK(&so->so_snd);
	so->so_snd.sb_lowat = sizeof(struct nad_wire_msg);
	soupcall_set(so, SO_SND, nad_supcall, sc);
	SOCKBUF_UNLOCK(&so->so_snd);

	bzero(&opt, sizeof(struct sockopt));
	opt.sopt_dir = SOPT_SET;
	opt.sopt_level = SOL_SOCKET;
	opt.sopt_name = SO_KEEPALIVE;
	opt.sopt_val = &val;
	opt.sopt_valsize = sizeof(val);
	val = 1;
	err = sosetopt(so, &opt);
	if (err)
		printf("%s: KEEPALIVE setting failed %d\n", __func__, err);

	opt.sopt_level = IPPROTO_TCP;
	opt.sopt_name = TCP_NODELAY;
	val = 1;
	err = sosetopt(so, &opt);
	if(err)
		printf("%s: NODELAY setting failed %d\n", __func__, err);

	opt.sopt_name = TCP_KEEPINIT;
	val = 3;
	err = sosetopt(so, &opt);
	if (err)
		printf("%s: KEEPINIT setting failed %d\n", __func__, err);

	opt.sopt_name = TCP_KEEPIDLE;
	val = 1;
	err = sosetopt(so, &opt);
	if (err)
		printf("%s: KEEPIDLE setting failed %d\n", __func__, err);

	opt.sopt_name = TCP_KEEPINTVL;
	val = 1;
	err = sosetopt(so, &opt);
	if (err)
		printf("%s: KEEPINTVL setting failed %d\n", __func__, err);

	opt.sopt_name = TCP_KEEPCNT;
	val = 5;
	err = sosetopt(so, &opt);
	if (err)
		printf("%s: KEEPCNT setting failed %d\n", __func__, err);
}

static int
nad_connect_socket(struct nad_softc *sc) {
	struct thread *td = curthread;
	struct sockaddr_in sa;
	struct socket *so;
	int error;

	error = socreate(PF_INET, &so, SOCK_STREAM,
	    IPPROTO_TCP, td->td_ucred, td);

	if (error != 0) {
		printf("%s: socreate() error %d\n", __func__, error);
		return (error);
	}

	sc->nad_so = so;
    nad_setup_socket(sc);
    memset(&sa, 0, sizeof(sa));
    sa.sin_len = sizeof(struct sockaddr_in);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(sc->port);
    sa.sin_addr.s_addr = htonl((127 << 24) + (0 << 16) + (0 << 8) + 1);
    error = soconnect(so, (struct sockaddr *)&sa, td);
    if(error) {
		printf("%s: soconnect() error %d\n", __func__, error);
        goto errout;
    }

    return(0);

errout:
    nad_close_socket(sc);
    return(error);
}

static void 
g_nad_init(struct g_class *mp __unused) {
    if(nad_debug) {
        printf("%s called\n", __func__);
    }
    sx_init(&nad_sx, "NAD config lock");
    g_topology_unlock();
    status_dev = make_dev(&nadctl_cdevsw, INT_MAX, UID_ROOT, GID_WHEEL, 0600,
            NADCTL_NAME);
    g_topology_lock();

    if(nad_debug) {
        printf("%s %s created\n", __func__, NADCTL_NAME);
    }
}

static void 
g_nad_start(struct bio *bp) {
    struct nad_softc *sc;
    sc = bp->bio_to->geom->softc;
    if((bp->bio_cmd == BIO_READ) || (bp->bio_cmd == BIO_WRITE)) {
        mtx_lock(&sc->stat_mtx);
        devstat_start_transaction_bio(sc->devstat, bp);
        mtx_unlock(&sc->stat_mtx);
    }

    mtx_lock(&sc->queue_mtx);
    bioq_disksort(&sc->bio_queue, bp);
    mtx_unlock(&sc->queue_mtx);
    wakeup(sc);
}

static int
g_nad_access(struct g_provider *pp, int r, int w, int e)
{
	struct nad_softc *sc;

	sc = pp->geom->softc;
	if (sc == NULL) {
		if (r <= 0 && w <= 0 && e <= 0)
			return (0);
		return (ENXIO);
	}
	r += pp->acr;
	w += pp->acw;
	e += pp->ace;
	if ((sc->flags & NAD_READONLY) != 0 && w > 0)
		return (EROFS);
	if ((pp->acr + pp->acw + pp->ace) == 0 && (r + w + e) > 0) {
		sc->opencount = 1;
	} else if ((pp->acr + pp->acw + pp->ace) > 0 && (r + w + e) == 0) {
		sc->opencount = 0;
	}
	return(0);
}

static void 
g_nad_dumpconf(struct sbuf *sb, const char *indent, struct g_geom *gp, 
        struct g_consumer *cp __unused, struct g_provider *pp) {
    struct nad_softc *mp;
    mp = gp->softc;
    if(pp != NULL) {
        if(indent != NULL) {
            sbuf_printf(sb, " u %d", mp->unit);
            sbuf_printf(sb, " s %ju", (uintmax_t) mp->sectorsize);
            sbuf_printf(sb, " l %ju", (uintmax_t) mp->mediasize);
            sbuf_printf(sb, " p %d", mp->port);
        } else {
            sbuf_printf(sb, "%s<unit>%d</unit>\n", indent,
                    mp->unit);
            sbuf_printf(sb, "%s<sectorsize>%ju</sectorsize>\n", indent,
                    (uintmax_t) mp->sectorsize);
            sbuf_printf(sb, "%s<port>%ju</port>\n", indent,
                    (uintmax_t) mp->port);
            sbuf_printf(sb, "%s<length>%ju</length>\n", indent,
                    (uintmax_t) mp->mediasize);

        }
    }
}

static void
g_nad_fini(struct g_class *mp __unused) {
    sx_destroy(&nad_sx);
    if(status_dev != NULL) {
        destroy_dev(status_dev);
    }
}

