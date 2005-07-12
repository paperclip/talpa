/*
 * TALPA test program
 *
 * Copyright (C) 2004 Sophos Plc, Oxford, England.
 *
 * This program is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License Version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program; if not,
 * write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 */

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>
#include <linux/unistd.h>

#include "tlp-test.h"
#include "modules/tlp-test.h"
#include "include/talpa-vettingclient.h"


#define VC_DEVICE "/dev/talpa-vcdevice"

static int autodetect_and_create(void)
{
    int fd;
    char line[256];
    char name[128];
    int pos;
    int rc;
    int minor;


    fd = open("/proc/misc", O_RDONLY);

    if ( fd < 0 )
    {
        return -1;
    }

    read_line:
    pos = 0;
    do
    {
        rc = read(fd, &line[pos], 1);
        if ( line[pos] == '\n' )
        {
            line[pos] = 0;
            break;
        }
        pos++;
    } while ( rc );

    if ( rc )
    {
        rc = sscanf(line, "%d %s", &minor, name);
        if ( (rc != 2) || strcmp(name, "vetting-client") )
        {
            goto read_line;
        }

        rc = unlink(VC_DEVICE);
        rc = mknod(VC_DEVICE, S_IFCHR, makedev(10, minor));

        if ( rc < 0 )
        {
            close(fd);
            return -1;
        }
    }
    else
    {
        close(fd);
        return -1;
    }

    close(fd);

    return 0;
}

int main(int argc, char *argv[])
{
    int fd;
    struct TalpaPacket_Register reg;
    int rc;
    struct TalpaPacket_FAIL pkt;
    struct TalpaPacket_VettingResponse response;


    fd = open(VC_DEVICE,O_RDWR,0);

    if ( fd < 0 )
    {
        autodetect_and_create();
        fd = open(VC_DEVICE,O_RDWR,0);
    }

    if ( fd < 0 )
    {
        fprintf(stderr,"Failed to open talpa-test device!\n");
        return 1;
    }

    reg.group = 0;
    rc = ioctl(fd, TLPVCIOC_REGISTER, &reg);

    if ( rc < 0 )
    {
        fprintf(stderr,"Failed to register!\n");
        return 1;
    }

    rc = read(fd, &pkt, sizeof(struct TalpaProtocolHeader));

    if ( rc != sizeof(struct TalpaProtocolHeader) )
    {
        fprintf(stderr,"Read header failed!\n");
        return 1;
    }

    rc = read(fd, &pkt.errorCode, pkt.header.payloadLength);

    if ( rc != pkt.header.payloadLength )
    {
        fprintf(stderr,"Read payload failed!\n");
        return 1;
    }

    if ( (pkt.header.type != TALPA_PKT_FAIL) || (pkt.errorCode != 0) )
    {
        fprintf(stderr,"Wrong packet received!\n");
        return 1;
    }

    response.response = TALPA_ALLOW;

    rc = write(fd, &response, sizeof(response));

    if ( rc < 0 )
    {
        fprintf(stderr,"Write failed!\n");
        return 1;
    }

    close(fd);

    return 0;
}

