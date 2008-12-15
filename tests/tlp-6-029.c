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


    fd = open("/dev/talpa-test",O_RDWR,0);

    if ( fd < 0 )
    {
        fprintf(stderr,"Failed to open talpa-test device!\n");
        return 77;
    }

    strcpy(to.filename,"/tmp/talpa-file-object-test-file");
    to.flags = O_RDWR;
    to.mode = S_IRUSR;

    ret = open(to.filename, to.flags | O_TRUNC | O_CREAT, to.mode);

    if ( ret < 0 )
    {
        fprintf(stderr,"Create error!\n");
        close(fd);
        return 77;
    }

    close(ret);

    ret = ioctl(fd,TALPA_TEST_FILE_OPEN, &to);

    if ( ret >= 0 )
    {
        fprintf(stderr,"Open sucess!\n");
        ioctl(fd,TALPA_TEST_FILE_CLOSE);
        close(fd);
        return 77;
    }

    return 0;
}

