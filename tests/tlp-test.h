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

#include <sys/time.h>

/* Syslog searching */

int open_log(void);
int close_log(void);
int search_log(time_t timeout, const char* match);


/* Vetting client "library" */

#include "../include/talpa-vettingclient.h"

int vc_init(unsigned int group, unsigned int timeout_ms);
int vc_exit(int handle);
struct TalpaPacket_VettingDetails* vc_get(int handle);
void vc_release(int handle, struct TalpaPacket_VettingDetails* details);
int vc_respond(int handle, struct TalpaPacket_VettingDetails* details, ETalpaProtocolResponse response);


/* Misc stuff */

#define test(code, cmd) \
do \
{ \
    if ( !cmd ) \
    { \
        fprintf(stderr,"Fail code %d - %d!\n",code, errno); \
        return code; \
    } \
} while(0)

#define testi(code, cmd) \
do \
{ \
    if ( cmd ) \
    { \
        fprintf(stderr,"Fail code %d - %d!\n",code, errno); \
        return code; \
    } \
} while(0)

#define lf2zero(var) \
do \
{ \
    int n; \
    for(n = 0; n < sizeof(var); n++) \
    { \
        if ( var[n] == '\n' ) \
        { \
            var[n] = 0; \
            break; \
        } \
    } \
} while(0)
