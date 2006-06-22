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
#include <sys/wait.h>
#include <pthread.h>
#include <signal.h>

#include "../include/talpa-vettingclient.h"
#include "../src/ifaces/intercept_filters/eintercept_action.h"
#include "../clients/vc.h"


int main(int argc, char *argv[])
{
    const unsigned int tout = 1;
    char file[100];
    char string[100];
    int talpa;
    int rc;
    struct TalpaPacket_VettingDetails* details;
    struct TalpaPacketFragment_FileDetails* fdetails;
    char* fname;
    int status;
    int ok = 0;

    if ( argc == 3 )
    {
        strcpy(file, argv[1]);
        strcpy(string, argv[2]);
    }
    else
    {
        strcpy(file, "/bin/true");
        strcpy(string, "/bin/true");
    }

    if ( (talpa = vc_init(0, tout*1000)) < 0 )
    {
        fprintf(stderr, "Failed to initialize!\n");
        return -1;
    }

    rc = fork();

    if ( !rc )
    {
        if ( execl(file, file, NULL) )
        {
            fprintf(stderr, "Failed to exec %s (%d)!\n", file, errno);
            return -1;
        }
    }
    else if ( rc < 0 )
    {
        fprintf(stderr, "Fork failed!\n");
        return -1;
    }

    details = vc_get(talpa);

    if ( !details )
    {
        fprintf(stderr, "Nothing caught!\n");
        vc_exit(talpa);
        wait(NULL);
        return -1;
    }

    if ( vc_respond(talpa, details, TALPA_ALLOW) < 0 )
    {
        fprintf(stderr, "Respond error!\n");
        vc_exit(talpa);
        wait(NULL);
        return -1;
    }

    fdetails = vc_file_frag(details);
    fname = vc_file_name(fdetails);

    if ( !strcmp(fname, string) )
    {
        ok = 1;
    }

    details = vc_get(talpa);

    if ( !details )
    {
        fprintf(stderr, "Nothing caught 2!\n");
        vc_exit(talpa);
        wait(NULL);
        return -1;
    }

    if ( vc_respond(talpa, details, TALPA_ALLOW) < 0 )
    {
        fprintf(stderr, "Respond error 2!\n");
        vc_exit(talpa);
        wait(NULL);
        return -1;
    }

    fdetails = vc_file_frag(details);
    fname = vc_file_name(fdetails);

    /* Wait for one more if we are under 2.6 kernel */
    details = vc_get(talpa);

    if ( details )
    {
        vc_respond(talpa, details, TALPA_ALLOW);
    }

    wait(&status);

    if ( ok )
    {
        vc_exit(talpa);
        return 0;
    }

    if ( strcmp(fname, string) )
    {
        fprintf(stderr, "String mismatch %s != %s!\n", fname, string);
        vc_exit(talpa);
        return -1;
    }

    if ( !WIFEXITED(status) )
    {
        fprintf(stderr, "Child error!\n");
        vc_exit(talpa);
        return -1;
    }

    if ( WEXITSTATUS(status) )
    {
        fprintf(stderr, "Child exec failed!\n");
        vc_exit(talpa);
        return -1;
    }

    vc_exit(talpa);

    return 0;
}

