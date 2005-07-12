/*
 * TALPA test program
 *
 * TALPA Filesystem Interceptor
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
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/poll.h>

#include "pe.h"

#define PE_DEVICE "/dev/talpa-pedevice"

static int autodetect_and_create(void)
{
    char line[16];
    int rc;
    int major, minor;
    int fd = open("/proc/sys/talpa/filter-interfaces/DeviceDriverProcessExclusion/device", O_RDONLY);

    if ( fd < 0 )
    {
        return -1;
    }

    rc = read(fd, line, sizeof(line));
    close(fd);
    rc = sscanf(line, "%d,%d", &major, &minor);

    if ( rc != 2 )
    {
        return -1;
    }

    rc = unlink(PE_DEVICE);
    rc = mknod(PE_DEVICE, S_IFCHR, makedev(major, minor));

    if ( rc < 0 )
    {
        return -1;
    }

    return 0;
}

int pe_init(void)
{
    int retried = 0;
    int rc;
    int fd;


    retry:
    fd = open(PE_DEVICE, O_RDWR);

    if ( fd < 0 )
    {
        if ( autodetect_and_create() )
        {
            return -1;
        }
        else if ( !retried )
        {
            retried = 1;
            goto retry;
        }
        return -1;
    }

    rc = ioctl(fd, TLPPEIOC_ACTIVE);
    if ( rc < 0 )
    {
        close(fd);
        if ( autodetect_and_create() )
        {
            return -1;
        }
        else if ( !retried )
        {
            retried = 1;
            goto retry;
        }
        return -1;
    }

    rc = ioctl(fd, TLPPEIOC_IDLE);
    if ( rc < 0 )
    {
        close(fd);
        if ( autodetect_and_create() )
        {
            return -1;
        }
        else if ( !retried )
        {
            retried = 1;
            goto retry;
        }
        return -1;
    }

    return fd;
}

int pe_exit(int handle)
{
    return close(handle);
}

int pe_active(int handle)
{
    return ioctl(handle, TLPPEIOC_ACTIVE);
}

int pe_idle(int handle)
{
    return ioctl(handle, TLPPEIOC_IDLE);
}
