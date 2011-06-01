/*
 * TALPA test program
 *
 * Copyright (C) 2004-2011 Sophos Limited, Oxford, England.
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
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>

#include "tlp-test.h"
#include "modules/tlp-test.h"

int main(int argc, char *argv[])
{
    int fd;
    int ret;
    struct talpa_open to;
    struct talpa_seek ts;
    unsigned int len;


    fd = open("/dev/talpa-test",O_RDWR,0);

    if ( fd < 0 )
    {
        fprintf(stderr,"Failed to open talpa-test device!\n");
        return 1;
    }

    strcpy(to.filename,"/bin/bash");
    to.flags = O_RDONLY;
    to.mode = S_IRUSR | S_IWUSR;

    ret = ioctl(fd,TALPA_TEST_FILE_OPEN, &to);

    if ( ret < 0 )
    {
        fprintf(stderr,"Open error!\n");
        close(fd);
        return 1;
    }

    ret = ioctl(fd,TALPA_TEST_FILE_ISOPEN);

    if ( ret <= 0 )
    {
        fprintf(stderr,"isOpen error!\n");
        close(fd);
        return 1;
    }

    ret = ioctl(fd,TALPA_TEST_FILE_LENGTH);

    if ( ret < 0 )
    {
        fprintf(stderr,"length ioctl error!\n");
        close(fd);
        return 1;
    }

    len = ret;
    ts.offset = len / 2;
    ts.mode = SEEK_SET;

    ret = ioctl(fd,TALPA_TEST_FILE_SEEK, &ts);

    if ( ret < 0 )
    {
        fprintf(stderr,"Seek error!\n");
        close(fd);
        return 1;
    }

    if ( ret != (len/2) )
    {
        fprintf(stderr,"Bad seek!\n");
        close(fd);
        return 1;
    }

    ret = ioctl(fd,TALPA_TEST_FILE_CLOSE);

    if ( ret < 0 )
    {
        fprintf(stderr,"Close error!\n");
        close(fd);
        return 1;
    }

    ret = ioctl(fd,TALPA_TEST_FILE_ISOPEN);

    if ( ret > 0 )
    {
        fprintf(stderr,"isOpen error - file open after close!\n");
        close(fd);
        return 1;
    }

    close(fd);

    return 0;
}

