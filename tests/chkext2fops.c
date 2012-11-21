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
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <alloca.h>
#include <errno.h>

int main(int argc, char *argv[])
{
    unsigned int depth;
    unsigned int len;
    unsigned int i;
    char *root;
    char *dirname;
    char *filename;

    if ( argc == 5 )
    {
        root = argv[1];
        filename = argv[2];
        depth = atoi(argv[3]);
        len = atoi(argv[4]);
    }
    else
    {
        fprintf(stderr, "Usage: %s dirname filename depth dirlen\n", argv[0]);
        return 1;
    }

    dirname = alloca(len+2);
    if ( !dirname )
    {
        fprintf(stderr, "No stack space!\n");
        return 2;
    }

    memset(dirname, '0', len);
    dirname[len] = 0;

    if ( chdir(root) < 0 )
    {
        fprintf(stderr, "Failed to chdir to %s (%d)!\n", root, errno);
        return 3;
    }

    for ( i = 0; i < depth; i++ )
    {
        if ( mkdir(dirname, 0700) < 0 )
        {
            fprintf(stderr, "Failed to mkdir n.%u (%d)!\n", i, errno);
            return 4;
        }
        if ( chdir(dirname) < 0 )
        {
            fprintf(stderr, "Failed to chdir n.%u (%d)!\n", i, errno);
            return 5;
        }
    }

    if ( creat(filename, O_CREAT | O_TRUNC) < 0 )
    {
        fprintf(stderr, "Failed to create file (%d)!\n", errno);
        return 10+errno;
    }

    return 0;
}
