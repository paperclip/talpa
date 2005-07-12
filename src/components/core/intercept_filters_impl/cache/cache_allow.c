/*
 * cache_allow.c
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

#define TALPA_SUBSYS "cache-allow"
#include "common/talpa.h"
#include "cache_allow.h"

/*
 * Forward declare implementation methods.
 */
static void examineFile(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFileInfo* info, IFile* file);
static void examineFilesystem(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFilesystemInfo* info);

static bool enable(void* self);
static void disable(void* self);
static bool isEnabled(const void* self);

static void deleteCacheAllow(struct tag_CacheAllow* object);

/*
 * Template Object.
 */
static CacheAllow template_CacheAllow =
    {
        {
            examineFile,
            examineFilesystem,
            enable,
            disable,
            isEnabled,
            0,
            (void (*)(void*))deleteCacheAllow
        },
        deleteCacheAllow,
        NULL
};
#define this    ((CacheAllow*)self)

/*
 * Object creation/destruction.
 */
CacheAllow* newCacheAllow(ICache* cache)
{
    CacheAllow* object;


    object = kmalloc(sizeof(template_CacheAllow), SLAB_KERNEL);
    if (object != 0)
    {
        memcpy(object, &template_CacheAllow, sizeof(template_CacheAllow));
        object->i_IInterceptFilter.object = object;
        object->mCache = cache;
    }
    return object;
}

static void deleteCacheAllow(struct tag_CacheAllow* object)
{
    kfree(object);
    return;
}

/*
 * IInterceptFilter.
 */

static void examineFile(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFileInfo* info, IFile* file)
{
    /* If the file is writable on open we will try to delete it from the cache. */
    if ( ( info->operation(info) == EFS_Open ) && info->isWritable(info) )
    {
        this->mCache->clear(this->mCache->object, info->device(info), info->inode(info));
        return;
    }

    /* If the access was allowed by an external vetting client add it to the cache */
    /* Do not cache the file if it is writable by somebody. */
    if ( report->hasBeenExternallyVetted(report) && !info->isWritableAnywhere(info) )
    {
        this->mCache->add(this->mCache->object, info->fsType(info), info->device(info), info->inode(info));
    }

    return;
}

static void examineFilesystem(const void* self, IEvaluationReport* report,
                                const IPersonality* userInfo,
                                const IFilesystemInfo* info)
{
    /* Purge all cached entries associated with this device on un-mount */
    if ( info->operation(info) == EFS_Umount )
    {
        this->mCache->purge(this->mCache->object, info->device(info));
    }

    return;
}

static bool enable(void* self)
{
    return this->mCache->enable(this->mCache->object);
}

static void disable(void* self)
{
    this->mCache->disable(this->mCache->object);
    return;
}

static bool isEnabled(const void* self)
{
    return this->mCache->isEnabled(this->mCache->object);
}


/*
 * End of cache_allow.c
 */

