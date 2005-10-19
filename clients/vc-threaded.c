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


struct vc_thread
{
    pthread_t       pt;
    unsigned int    id;
    unsigned int    group;
    unsigned int    timeout;
    unsigned int    run;
};

void* vc(void* param)
{
    struct vc_thread* vct = (struct vc_thread *)param;
    int talpa;
    sigset_t intset;
    struct TalpaPacket_VettingDetails* packet = NULL;
    struct TalpaPacketFragment_FileDetails* file;
    struct TalpaPacketFragment_FilesystemDetails* filesystem;


    sigemptyset(&intset);
    sigaddset(&intset, SIGINT);

    pthread_sigmask(SIG_BLOCK, &intset, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

    if ( (talpa = vc_init(vct->group, vct->timeout)) < 0 )
    {
        fprintf(stderr, "Failed to initialize!\n");
        return NULL;
    }

    printf("[%u] Registered to group %u\n", vct->id, vct->group);

    printf("---------------------------------------------------------------------\n");

    while ( vct->run )
    {
        if ( packet )
        {
            vc_release(talpa, packet);
        }

        packet = vc_get(talpa);

        if ( !packet )
        {
            continue;
        }

        printf("[%u] Packet: 0x%x,  payload: %u\n", vct->id, packet->header.type, packet->header.payloadLength);

        if ( packet->header.type & TALPA_PKT_FILEDETAIL )
        {
            file = vc_file_frag(packet);
            printf("[%u] Rootdir: %*s, File: %s\n", vct->id, packet->rootdir_len, vc_file_name(file), vc_file_name(file));
            if ( !packet->responseReqd )
            {
                printf("---------------------------------------------------------------------\n");
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
            filesystem = vc_filesystem_frag(packet);
            printf("[%u] Dev: %s\n", vct->id, vc_filesystem_dev(filesystem));
            if ( !packet->responseReqd )
            {
                printf("---------------------------------------------------------------------\n");
                continue;
            }
        }
        else
        {
            continue;
        }

        printf("[%u] Allowing access...", vct->id);
        if ( vc_respond(talpa, packet, TALPA_ALLOW) < 0 )
        {
            printf("Error %d!\n", errno);
            continue;
        }
        else
        {
            printf("Ok.\n");
        }
        printf("---------------------------------------------------------------------\n");
    }

    vc_exit(talpa);

    return NULL;
}

unsigned int nr_threads = 2;
struct vc_thread *threads;

void sigint(int val)
{
    unsigned int t;

    printf("Interrupted!\n");

    for ( t = 0; t < nr_threads; t++ )
    {
        threads[t].run = 0;
        pthread_kill(threads[t].pt, SIGUSR1);
    }
}

void sigusr1(int val)
{
    return;
}

int main(int argc, char *argv[])
{
    struct sigaction intact, usr1act;
    sigset_t intset, usr1set;
    unsigned int running = 0;
    unsigned int t;
    int rc;


    if ( argc == 2 )
    {
        nr_threads = atoi(argv[1]);
    }

    threads = (struct vc_thread *)malloc(sizeof(struct vc_thread) * nr_threads);

    printf("Will spawn %u threads.\n", nr_threads);

    sigemptyset(&intset);
    sigemptyset(&usr1set);
    sigaddset(&intset, SIGINT);
    sigaddset(&usr1set, SIGUSR1);
    intact.sa_handler = sigint;
    intact.sa_mask = intset;
    usr1act.sa_handler = sigusr1;
    usr1act.sa_mask = usr1set;
    sigaction(SIGINT, &intact, NULL);
    sigaction(SIGUSR1, &usr1act, NULL);

    for ( t = 0; t < nr_threads; t++ )
    {
        threads[t].run = 1;
        threads[t].id = t;
        threads[t].group = 0;
        threads[t].timeout = 0;
        rc = pthread_create(&threads[t].pt, NULL, vc, &threads[t]);
        if ( rc )
        {
            printf("Spawning thread %u failed (%d)!\n", t, errno);
        }
        else
        {
            running++;
        }
    }

    while ( running )
    {
        for ( t = 0; t < nr_threads; t++ )
        {
            if ( !pthread_join(threads[t].pt, NULL) )
            {
                running--;
            }
        }
    }

    return 0;
}
