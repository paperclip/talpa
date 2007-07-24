/*
 * cache_eval.c
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

#define TALPA_SUBSYS "cache-eval"
#include "common/talpa.h"
#include "cache_eval.h"

#include "platform/alloc.h"

/*
 * Forward declare implementation methods.
 */
static void examineFile(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFileInfo* info, IFile* file);
static EInterceptAction examineInode(const void* self, const EFilesystemOperation op, const bool writable, const uint32_t device, const uint32_t inode);

static bool enable(void* self);
static void disable(void* self);
static bool isEnabled(const void* self);

static void deleteCacheEval(struct tag_CacheEval* object);

/*
 * Template Object.
 */
static CacheEval template_CacheEval =
    {
        {
            examineFile,
            examineInode,
            NULL,
            enable,
            disable,
            isEnabled,
            NULL,
            (void (*)(void*))deleteCacheEval
        },
        deleteCacheEval,
        NULL
};
#define this    ((CacheEval*)self)

/*
 * Object creation/destruction.
 */
CacheEval* newCacheEval(ICache* cache)
{
    CacheEval* object;


    object = talpa_alloc(sizeof(template_CacheEval));
    if ( object )
    {
        memcpy(object, &template_CacheEval, sizeof(template_CacheEval));
        object->i_IInterceptFilter.object = object;
        object->mCache = cache;
    }
    return object;
}

static void deleteCacheEval(struct tag_CacheEval* object)
{
    talpa_free(object);
    return;
}

/*
 * IInterceptFilter.
 */

static void examineFile(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFileInfo* info, IFile* file)
{
    /* Do not check if cached on close */
    if ( unlikely( info->operation(info) == EFS_Close ) )
    {
        return;
    }

    if ( this->mCache->find(this->mCache->object, info->device(info), info->inode(info)) > 0 )
    {
        report->setRecommendedAction(report, EIA_Allow);
        return;
    }

    return;
}

static EInterceptAction examineInode(const void* self, const EFilesystemOperation op, const bool writable, const uint32_t device, const uint32_t inode)
{
    /* Do not check if cached on close */
    if ( unlikely( op == EFS_Close ) )
    {
        return EIA_Next;
    }

    if ( this->mCache->find(this->mCache->object, device, inode) > 0 )
    {
        return EIA_Allow;
    }

    return EIA_Next;
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
 * End of cache_eval.c
 */

