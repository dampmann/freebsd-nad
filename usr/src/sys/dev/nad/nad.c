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

static g_init_t g_nad_init;
static g_fini_t g_nad_fini;
static g_start_t g_nad_start;
static g_access_t g_nad_access;
static void g_nad_dumpconf(struct sbuf *sb, const char *indent, 
        struct g_geom *gp, struct g_consumer *cp __unused, struct g_provider *pp); 

static struct sx nad_sx;
static struct cdev *status_dev = 0;
static d_ioctl_t nadctlioctl;

struct vdisk_buffer {
    char *buffer;
    struct mtx m;
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
    struct proc *procp;
    struct g_geom *gp;
    struct g_provider *pp;
    struct socket *nad_so;
    int (*start)(struct nad_softc *sc, struct bio *bp);
    struct devstat *devstat;
    struct vdisk_buffer *vdisk;
    int port;
    int opencount;
};

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
nadthread(void *arg) {
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
            msleep(sc, &sc->queue_mtx, PRIBIO | PDROP, "nadwait", 0);
            continue;
        }

        mtx_unlock(&sc->queue_mtx);

        if (bp->bio_cmd == BIO_GETATTR) {
            error = EOPNOTSUPP;
        } else {
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
    printf("malloc media\n");
    sc->vdisk->buffer = malloc(mediasize*sizeof(char), M_NAD, M_WAITOK | M_ZERO);
    mtx_init(&sc->vdisk->m, "nad vdisk buffer", NULL, MTX_DEF);
    bioq_init(&sc->bio_queue);
    mtx_init(&sc->queue_mtx, "nad bio queue", NULL, MTX_DEF);
    mtx_init(&sc->stat_mtx, "nad stat", NULL, MTX_DEF);
    sc->unit = unit;
    sc->port = port;
    sc->opencount = 0;
    sc->mediasize = mediasize;
    if(unit < 10) {
        sprintf(sc->name, "nad00%d", unit);
    } else if(unit < 100) {
        sprintf(sc->name, "nad0%d", unit);
    } else {
        sprintf(sc->name, "nad%d", unit);
    }
    LIST_INSERT_HEAD(&nad_softc_list, sc, list);
    error = kproc_create(nadthread, sc, &sc->procp, 0, 0, "%s", sc->name);
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
        msleep(sc->procp, &sc->queue_mtx, PRIBIO, "naddestroy", hz/10);
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
            sc->start = naddoio;
            nadnewprovider(sc);
            return(0);
        case NADIOCDETACH:
            sc = nadfind(nadio->nad_unit);
            if(sc == NULL)
                return(ENOENT);
            if(sc->opencount != 0)
                return(EBUSY);
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
/*
static int
nad_connect(struct nad_softc *sc) {
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
}
*/
static void 
g_nad_init(struct g_class *mp __unused) {
    sx_init(&nad_sx, "NAD config lock");
    g_topology_unlock();
    status_dev = make_dev(&nadctl_cdevsw, INT_MAX, UID_ROOT, GID_WHEEL, 0600,
            NADCTL_NAME);
    g_topology_lock();
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

