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
#include <sys/devicestat.h>
#include <sys/ioctl.h>
#include <sys/linker.h>
#include <sys/nadioctl.h>
#include <sys/module.h>
#include <sys/resource.h>
#include <sys/stat.h>

#include <assert.h>
#include <devstat.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libgeom.h>
#include <libutil.h>
#include <paths.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static struct nad_ioctl nadio;
static enum {UNSET, ATTACH, DETACH} action = UNSET;

static void usage(void);

#define CLASS_NAME_NAD	"NAD"

static void
usage(void)
{

	fprintf(stderr,
"usage: nadconfig -a -s mediasize -S sectorsize -u unit -p port\n"
"       nadconfig -d -u unit [-o [no]force]\n");
	fprintf(stderr, "\tmediasize = %%d (512 byte blocks), %%db (B),\n");
	fprintf(stderr, "\t       %%dk (kB), %%dm (MB), %%dg (GB), \n");
	fprintf(stderr, "\t       %%dt (TB), or %%dp (PB)\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	int ch, fd, i;
	char *p;
	char *sflag = NULL, *uflag = NULL, *pflag = NULL, *ssflag = NULL;

	bzero(&nadio, sizeof(nadio));

	if (argc == 1)
		usage();

	while ((ch = getopt(argc, argv, "ado:s:S:u:p:")) != -1) {
		switch (ch) {
		case 'a':
			if (action != UNSET && action != ATTACH)
				errx(1, "-a is mutually exclusive "
				    "with -d, and -l");
			action = ATTACH;
			break;
		case 'd':
			if (action != UNSET && action != DETACH)
				errx(1, "-d is mutually exclusive "
				    "with -a, and -l");
			action = DETACH;
			break;
		case 'o':
			if(!strcmp(optarg, "force"))
				nadio.nad_options |= NAD_FORCE;
			else
				errx(1, "unknown option: %s", optarg);
			break;
		case 'S':
			if (ssflag != NULL)
				errx(1, "-S can be passed only once");
			ssflag = optarg;
			nadio.nad_sectorsize = (int)strtoumax(optarg, &p, 0);
			if (p == NULL || *p == '\0')
                ;
			else if (*p == 'b' || *p == 'B')
				; /* do nothing */
			else if (*p == 'k' || *p == 'K')
				nadio.nad_sectorsize <<= 10;
			else if (*p == 'm' || *p == 'M')
				nadio.nad_sectorsize <<= 20;
			else if (*p == 'g' || *p == 'G')
				errx(1, "sector size can't be in GB");
			else if (*p == 't' || *p == 'T') {
				errx(1, "sector size can't be in TB");
			} else if (*p == 'p' || *p == 'P') {
				errx(1, "sector size can't be in PB");
			} else
				errx(1, "unknown suffix on -S argument");
			break;
		case 's':
			if (sflag != NULL)
				errx(1, "-s can be passed only once");
			sflag = optarg;
			nadio.nad_mediasize = (off_t)strtoumax(optarg, &p, 0);
			if (p == NULL || *p == '\0')
				nadio.nad_mediasize *= DEV_BSIZE;
			else if (*p == 'b' || *p == 'B')
				; /* do nothing */
			else if (*p == 'k' || *p == 'K')
				nadio.nad_mediasize <<= 10;
			else if (*p == 'm' || *p == 'M')
				nadio.nad_mediasize <<= 20;
			else if (*p == 'g' || *p == 'G')
				nadio.nad_mediasize <<= 30;
			else if (*p == 't' || *p == 'T') {
				nadio.nad_mediasize <<= 30;
				nadio.nad_mediasize <<= 10;
			} else if (*p == 'p' || *p == 'P') {
				nadio.nad_mediasize <<= 30;
				nadio.nad_mediasize <<= 20;
			} else
				errx(1, "unknown suffix on -s argument");
			break;
        case 'u':
            if(uflag != NULL)
                errx(1, "-u can be passed only once");
            uflag = optarg;
            errno = 0;
            nadio.nad_unit = (int)strtoumax(optarg, &p, 0);
            if(p == NULL || errno == EINVAL)
                errx(1, "-u has to be followed by a number between 0 and 999 %s", uflag);
            break;
        case 'p':
            if(pflag != NULL)
                errx(1, "-p can be passed only once");
            pflag = optarg;
            errno = 0;
            nadio.nad_port = (int)strtoumax(optarg, &p, 0);
            if(p == NULL || errno == EINVAL)
                errx(1, "-p has to be followed by a port number > 1024%s", pflag);
            break;
        /*
		case 'x':
			mdio.md_fwsectors = strtoul(optarg, &p, 0);
			break;
		case 'y':
			mdio.md_fwheads = strtoul(optarg, &p, 0);
			break;
        */
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (action == UNSET)
		action = ATTACH;

	nadio.nad_version = NADIO_VERSION;

	if (!kld_isloaded("g_nad") && kld_load("geom_nad") == -1)
		err(1, "failed to load geom_nad module");

	fd = open(_PATH_DEV NADCTL_NAME, O_RDWR, 0);
	if (fd < 0)
		err(1, "open(%s%s)", _PATH_DEV, NADCTL_NAME);

	if (action == ATTACH) {
		i = ioctl(fd, NADIOCATTACH, &nadio);
		if (i < 0)
			err(1, "ioctl(%s%s)", _PATH_DEV, NADCTL_NAME);
	} else if (action == DETACH) {
		i = ioctl(fd, NADIOCDETACH, &nadio);
		if (i < 0)
			err(1, "ioctl(%s%s)", _PATH_DEV, NADCTL_NAME);
	} else
		usage();
	close(fd);
	return (0);
}

