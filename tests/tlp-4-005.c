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
#include <sys/wait.h>
#include <pthread.h>
#include <signal.h>

#include "../clients/pe.h"


void* pe_thread(void* param)
{
    int pe;

    if (  (pe = pe_init()) < 0 )
    {
        fprintf(stderr, "Thread failed to initialize PE!\n");
        pthread_exit((void *)~0UL);
    }

    pe_active(pe);
    pe_idle(pe);

    pe_exit(pe);

    return NULL;
}


int main(int argc, char *argv[])
{
    int pe;
    int rc;
    pthread_t thread;
    void *tret;

    if (  (pe = pe_init()) < 0 )
    {
        fprintf(stderr, "Failed to initialize PE!\n");
        return -1;
    }

    rc = pthread_create(&thread, NULL, pe_thread, NULL);
    if ( rc )
    {
        printf("Spawning thread failed (%d)!\n", errno);
        return -2;
    }

    pthread_join(thread, &tret);

    if ( tret )
    {
        return -3;
    }

    pe_active(pe);
    pe_idle(pe);

    pe_exit(pe);

    return 0;
}

