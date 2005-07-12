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
#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>


int main(int argc, char *argv[])
{
    unsigned int loops = 2000000;
    int fd;
    time_t start;
    time_t end;


    if ( argc == 2 )
    {
        loops = atoi(argv[1]);
    }

    start = time(NULL);
    while ( time(NULL) == start );
    start = time(NULL);
    while ( loops-- )
    {
        fd = open("/bin/ls", O_RDONLY);
        close(fd);
    }
    end = time(NULL);

    printf("%d seconds\n", end - start);

    return 0;
}
