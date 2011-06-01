/*
 * cache_deny.c
 *
 * TALPA Filesystem Interceptor
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

#include <linux/kernel.h>

#define TALPA_SUBSYS "cache-deny"
#include "common/talpa.h"
#include "cache_deny.h"

#include "platform/alloc.h"

/*
 * Forward declare implementation methods.
 */
static void examineFile(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFileInfo* info, IFile* file);
static void examineFilesystem(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFilesystemInfo* info);

static bool enable(void* self);
static void disable(void* self);
static bool isEnabled(const void* self);

static void deleteCacheDeny(struct tag_CacheDeny* object);

/*
 * Template Object.
 */
static CacheDeny template_CacheDeny =
    {
        {
            examineFile,
            NULL,
            examineFilesystem,
            enable,
            disable,
            isEnabled,
            NULL,
            (void (*)(void*))deleteCacheDeny
        },
        deleteCacheDeny,
        NULL
};
#define this    ((CacheDeny*)self)

/*
 * Object creation/destruction.
 */
CacheDeny* newCacheDeny(ICache* cache)
{
    CacheDeny* object;


    object = talpa_alloc(sizeof(template_CacheDeny));
    if ( object )
    {
        memcpy(object, &template_CacheDeny, sizeof(template_CacheDeny));
        object->i_IInterceptFilter.object = object;
        object->mCache = cache;
    }
    return object;
}

static void deleteCacheDeny(struct tag_CacheDeny* object)
{
    talpa_free(object);
    return;
}

/*
 * IInterceptFilter.
 */

static void examineFile(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFileInfo* info, IFile* file)
{
    /* If the access was denied, we will delete the file
        from our cache. But only if that is an external decision. */
    if ( likely(report->hasBeenExternallyVetted(report) == true) )
    {
        this->mCache->clear(this->mCache->object, info->device(info), info->inode(info));
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
    /* This filter is not allowed to enable the cache. */
    return false;
}

static void disable(void* self)
{
    /* This filter is not allowed to disable the cache. */
    return;
}

static bool isEnabled(const void* self)
{
    /* Status is inherited from the cache object. */
    return this->mCache->isEnabled(this->mCache->object);
}

/*
 * End of cache_deny.c
 */

