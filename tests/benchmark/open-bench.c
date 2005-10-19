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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
    char *file = "/bin/ls";
    unsigned int loops = 1000000;
    char *arg;
    unsigned int pos = 1;

    for ( ; argc > 1 ; pos++, argc-- )
    {
        arg = argv[pos];
        if ( !strncmp(arg, "-f", 2) )
        {
            arg += 2;
            file = arg;
        }
        else if ( !strncmp(arg, "-l", 2) )
        {
            arg += 2;
            loops = atol(arg);
        }
    }

    while ( loops-- )
    {
        close(open(file, O_RDONLY));
    }

    printf("%4.2fs\n", (float)clock() / (float)CLOCKS_PER_SEC);

    return 0;
}
