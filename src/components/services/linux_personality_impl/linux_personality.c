/*
 * linux_personality.c
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
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sched.h>

#include "common/talpa.h"
#include "linux_personality.h"

/*
 * Forward declare implementation methods.
 */
static void get(const void* self);
static uid_t uid(const void* self);
static uid_t euid(const void* self);
static uid_t fsuid(const void* self);
static gid_t gid(const void* self);
static gid_t egid(const void* self);
static void deleteLinuxPersonality(struct tag_LinuxPersonality* object);

/*
 * Template Object.
 */
static LinuxPersonality template_LinuxPersonality =
    {
        {
            get,
            uid,
            euid,
            fsuid,
            gid,
            egid,
            0,
            (void (*)(const void*))deleteLinuxPersonality
        },
        deleteLinuxPersonality,
        ATOMIC_INIT(1),
        0,
        0,
        0,
        0,
        0
    };
#define this    ((LinuxPersonality*)self)


/*
 * Object creation/destruction.
 */
LinuxPersonality* newLinuxPersonality(void)
{
    LinuxPersonality* object;


    object = kmalloc(sizeof(template_LinuxPersonality), GFP_KERNEL);
    if ( likely(object != 0) )
    {
        memcpy(object, &template_LinuxPersonality, sizeof(template_LinuxPersonality));
        object->i_IPersonality.object = object;

        object->mUID = current->uid;
        object->mEUID = current->euid;
        object->mFSUID = current->fsuid;
        object->mGID = current->gid;
        object->mEGID = current->egid;
    }

    return object;
}

static void deleteLinuxPersonality(struct tag_LinuxPersonality* object)
{
    if ( likely(object != 0) )
    {
        if ( atomic_dec_and_test(&object->mRefCnt) )
        {
            kfree(object);
        }
    }
    return;
}

/*
 * IPersonality.
 */
static void get(const void* self)
{
    atomic_inc(&this->mRefCnt);
    return;
}

static uid_t uid(const void* self)
{
    return this->mUID;
}

static uid_t euid(const void* self)
{
    return this->mEUID;
}

static gid_t gid(const void* self)
{
    return this->mGID;
}

static gid_t egid(const void* self)
{
    return this->mEGID;
}

static uid_t fsuid(const void* self)
{
    return this->mFSUID;
}
/*
 * End of linux_personality.c
 */

