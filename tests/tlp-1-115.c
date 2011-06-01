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
    char *tmpfile;
    int talpa;
    int rc;
    struct TalpaPacket_VettingDetails* details;
    int status;


    if ( argc == 2 )
    {
        tmpfile = argv[1];
    }
    else
    {
        fprintf(stderr, "Bad usage!\n");
        return 1;
    }

    if ( (talpa = vc_init(0, 2000)) < 0 )
    {
        fprintf(stderr, "Failed to initialize!\n");
        return -1;
    }

    rc = fork();

    if ( !rc )
    {
        int fd;
        int ret;

        fd = open(argv[1], O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR);
        if (fd < 0) {
            perror("Setup failed (provide filename, run as root)");
            return 1;
        }

        ret = setegid(4321);
        if (ret < 0) {
            perror("setegid failed (run me as root)");
            return 2;
        }

        ret = seteuid(4321);
        if (ret < 0) {
            perror("seteuid failed (run me as root)");
            return 3;
        }

        /* Scan on close should not fail. */
        close(fd);

        return 0;
    }
    else if ( rc < 0 )
    {
        fprintf(stderr, "Fork failed!\n");
        return -1;
    }

    details = vc_get(talpa);

    if ( !details )
    {
        fprintf(stderr, "No interception!\n");
        vc_exit(talpa);
        wait(NULL);
        return -1;
    }
    else
    {
        if ( vc_stream_length(talpa) < 0 )
        {
            fprintf(stderr, "No file stream!\n");
            vc_respond(talpa, details, TALPA_ALLOW);
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
    }

    wait(&status);

    if ( !WIFEXITED(status) )
    {
        fprintf(stderr, "Child error!\n");
        vc_exit(talpa);
        return -1;
    }

    if ( WEXITSTATUS(status) )
    {
        fprintf(stderr, "Child failed!\n");
        vc_exit(talpa);
        return -1;
    }

    vc_exit(talpa);

    return 0;
}

