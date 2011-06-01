/*
 * iintercept_processor.h
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
#ifndef H_IINTERCEPTPROCESSOR
#define H_IINTERCEPTPROCESSOR

#include "common/bool.h"
#include "filesystem/ifile.h"
#include "filesystem/ifile_info.h"
#include "filesystem/ifilesystem_info.h"
#include "intercept_filters/iintercept_filter.h"

typedef struct
{
    int   (*examineFileInfo)       (const void* self, const IFileInfo* info, IFile* file);
    int   (*examineInode)          (const void* self, const EFilesystemOperation op, const bool writable, const int flags, const uint32_t device, const uint32_t inode);
    int   (*runAllowChain)         (const void* self, const IFileInfo* info);
    int   (*examineFilesystemInfo) (const void* self, const IFilesystemInfo* info);
    void  (*addEvaluationFilter)   (void* self, IInterceptFilter* filter);
    void  (*addAllowFilter)        (void* self, IInterceptFilter* filter);
    void  (*addDenyFilter)         (void* self, IInterceptFilter* filter);
    void  (*removeEvaluationFilter)(void* self, const IInterceptFilter* filter);
    void  (*removeAllowFilter)     (void* self, const IInterceptFilter* filter);
    void  (*removeDenyFilter)      (void* self, const IInterceptFilter* filter);
    void  (*resetEvaluationFilters)(void* self);
    void  (*resetAllowFilters)     (void* self);
    void  (*resetDenyFilters)      (void* self);
    /*
     *  Object supporting this interface instance.
     */
    void* object;
    void  (*delete)                (void* self);
} IInterceptProcessor;

#endif

/*
 * End of iintercept_processor.h
 */

