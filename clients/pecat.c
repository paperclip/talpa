/*
 * TALPA test program
 *
 * TALPA Filesystem Interceptor
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
#include <pthread.h>
#include <signal.h>

#include "pe.h"



int main(int argc, char *argv[])
{
    int talpa;
    int fd;
    size_t size;
    char buffer[4096];
    int args = argc - 1;

    if (  (talpa = pe_init()) < 0 )
    {
        fprintf(stderr, "Failed to initialize!\n");
        return -1;
    }

    pe_active(talpa); /* Now we can read without being vetted */

    while ( args > 0 )
    {
        fd = open(argv[args], O_RDONLY);
        if ( fd > 0 )
        {
            while ( (size = read(fd, buffer, sizeof(buffer))) > 0 )
            {
                write(STDOUT_FILENO, buffer, size);
            }
            close(fd);
        }
        else
        {
            fprintf(stderr, "%s: %s!\n", argv[args], strerror(errno));
        }
        args--;
    }

    pe_idle(talpa); /* Not needed since we are about to exit but... */
    pe_exit(talpa);

    return 0;
}

