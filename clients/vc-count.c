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
#include <pthread.h>
#include <signal.h>

#include "vc.h"


int run = 1;

void sigint(int val)
{
#ifndef NDEBUG
    printf("Interrupted!\n");
#endif
    run = 0;
}

int main(int argc, char *argv[])
{
    struct sigaction intact, usr1act;
    sigset_t intset, usr1set;
    unsigned int group;
    int talpa;
    struct TalpaPacket_VettingDetails* packet = NULL;
    struct TalpaPacketFragment_FileDetails* file;
    struct TalpaPacketFragment_FilesystemDetails* filesystem;
    unsigned int scanned = 0;

    sigemptyset(&intset);
    sigaddset(&intset, SIGINT);
    intact.sa_handler = sigint;
    intact.sa_mask = intset;
    sigaction(SIGINT, &intact, NULL);

    if ( argc == 2 )
        group = atoi(argv[1]);
    else
        group = 0;

    if (  (talpa = vc_init(group, 0)) < 0 )
    {
        fprintf(stderr, "Failed to initialize!\n");
        return -1;
    }

    printf("Registered to group %u.\n\n", group);
    printf("Files scanned: 1234567890");

    while ( run )
    {
        printf("\b\b\b\b\b\b\b\b\b\b%10u", scanned);
        fflush(stdout);

        if ( packet )
        {
            vc_release(talpa, packet);
        }

        packet = vc_get(talpa);

        if ( !packet )
        {
            continue;
        }

        if ( packet->header.type & TALPA_PKT_FILEDETAIL )
        {
            file = (struct TalpaPacketFragment_FileDetails *)(((char *)packet) + sizeof(struct TalpaPacket_VettingDetails));
            if ( !packet->responseReqd )
            {
                continue;
            }
            #ifdef SCANFILE
            if ( S_ISREG(file->mode) )
            {
                vc_scan_stream(talpa);
            }
            #endif
        }
        else if ( packet->header.type & TALPA_PKT_FILESYSTEMDETAIL )
        {
            filesystem = (struct TalpaPacketFragment_FilesystemDetails *)(((char *)packet) + sizeof(struct TalpaPacket_VettingDetails));
            if ( !packet->responseReqd )
            {
                continue;
            }
        }
        else
        {
            continue;
        }

        if ( vc_respond(talpa, packet, TALPA_ALLOW) < 0 )
        {
            continue;
        }
        else
        {
            scanned++;
        }
    }

    vc_exit(talpa);

    return 0;
}



