/*
 * linux_personality.h
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
#ifndef H_LINUXPERSONALITY
#define H_LINUXPERSONALITY

#include <asm/atomic.h>

#include "personality/ipersonality.h"

typedef struct tag_LinuxPersonality
{
    IPersonality   i_IPersonality;
    void           (*delete)(struct tag_LinuxPersonality* object);

    atomic_t        mRefCnt;
    uid_t           mUID;
    uid_t           mEUID;
    uid_t           mFSUID;
    gid_t           mGID;
    gid_t           mEGID;
} LinuxPersonality;

/*
 * Object Creators.
 */
LinuxPersonality* newLinuxPersonality(void);


#endif

/*
 * End of linux_personality.h
 */


