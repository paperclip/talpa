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

#include "tlp-test.h"
#include "modules/tlp-test.h"
#include "src/ifaces/intercept_filters/eintercept_action.h"
#include "src/ifaces/filesystem/efilesystem_operation.h"

int main(int argc, char *argv[])
{
    int fd;
    int ret;
    struct talpa_file tf;


    fd = open("/dev/talpa-test",O_RDWR,0);

    if ( fd < 0 )
    {
        fprintf(stderr,"Failed to open talpa-test device!\n");
        return 1;
    }

    tf.operation = EFS_Open;
    tf.flags = O_RDONLY;
    strcpy(tf.name,"/bin/bash");
    strcpy(tf.fstype,"testfs");

    ret = ioctl(fd,TALPA_TEST_DEGRMODE_TIMEOUTS,100);

    if ( ret < 0 )
    {
        fprintf(stderr,"Set IOCTL error!\n");
        close(fd);
        return 1;
    }

    ret = ioctl(fd,TALPA_TEST_FILEINFO,&tf);

    if ( ret < 0 )
    {
        fprintf(stderr,"File IOCTL error!\n");
        close(fd);
        return 1;
    }
    else if ( ret != EIA_Allow )
    {
        fprintf(stderr,"Test error!\n");
        close(fd);
        return 1;
    }

    close(fd);

    return 0;
}

