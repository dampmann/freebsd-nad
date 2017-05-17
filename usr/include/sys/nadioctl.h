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

#ifndef __SYS_NADIOCTL_H
#define __SYS_NADIOCTL_H

struct nad_ioctl {
    unsigned nad_version;
    unsigned nad_unit;
    off_t nad_mediasize;
    unsigned nad_sectorsize;
    unsigned nad_options;
    int nad_port;
};

#define NAD_NAME "nad"
#define NADCTL_NAME "nadctl"
#define NADIO_VERSION 0

#define NADIOCATTACH _IOWR('n', 0, struct nad_ioctl)
#define NADIOCDETACH _IOWR('n', 1, struct nad_ioctl)

#define NAD_READONLY 0x01
#define NAD_FORCE 0x02

#endif

