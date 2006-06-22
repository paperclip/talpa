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
#include <linux/unistd.h>
#include <linux/types.h>
#include <linux/sysctl.h>

#include "tlp-test.h"
#include "modules/tlp-test.h"

_syscall1(int, _sysctl, struct __sysctl_args *, args);

int sysctl(int *name, int nlen, void *oldval, size_t *oldlenp,
           void *newval, size_t newlen)
{
        struct __sysctl_args args={name,nlen,oldval,oldlenp,newval,newlen};
        return _sysctl(&args);
}
#define SIZE(x) sizeof(x)/sizeof(x[0])
#define NAMESZ 16

int path[] = { 7700, 2, 1, 1 };
const char *testval = "garbage";

int main(int argc, char *argv[])
{
    char value1[NAMESZ];
    char value2[NAMESZ];
    char value3[NAMESZ];
    char blob[100000];
    int len = sizeof(value1);

    if ( sysctl(path, SIZE(path), value1, &len, 0, 0) )
    {
        fprintf(stderr, "Error reading value!\n");
        return -errno;
    }

    if ( sysctl(path, SIZE(path), 0, 0, (void *)testval, strlen(testval)) )
    {
        fprintf(stderr, "Error setting to %s!\n", testval);
        return -errno;
    }

    if ( sysctl(path, SIZE(path), value2, &len, 0, 0) )
    {
        fprintf(stderr, "Error reading value!\n");
        return -errno;
    }

    if ( strcmp(value1, value2) )
    {
        fprintf(stderr, "Compare 1 failed %s != %s\n", value1, value2);
        return -1;
    }

    if ( sysctl(path, SIZE(path), 0, 0, (void *)blob, sizeof(blob)) )
    {
        fprintf(stderr, "Error setting to BINARY BLOB!\n");
        return -errno;
    }

    if ( sysctl(path, SIZE(path), value3, &len, 0, 0) )
    {
        fprintf(stderr, "Error reading value!\n");
        return -errno;
    }

    if ( strcmp(value1, value3) )
    {
        fprintf(stderr, "Compare 2 failed %s != %s\n", value1, value3);
        return -1;
    }

    return 0;
}
