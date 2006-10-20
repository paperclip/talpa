/*
 * iintercept_filter.h
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
#ifndef H_IINTERCEPTFILTER
#define H_IINTERCEPTFILTER

#include "common/bool.h"
#include "personality/ipersonality.h"
#include "filesystem/ifile.h"
#include "filesystem/ifile_info.h"
#include "filesystem/ifilesystem_info.h"

#include "ievaluation_report.h"

typedef struct
{
    void                (*examineFile)       (const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFileInfo* info, IFile* file);
    EInterceptAction    (*examineInode)      (const void* self, const EFilesystemOperation op, const uint32_t device, const uint32_t inode);
    void                (*examineFilesystem) (const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFilesystemInfo* info);
    bool                (*enable)            (void* self);
    void                (*disable)           (void* self);
    bool                (*isEnabled)         (const void* self);
    /*
     *  Object supporting this interface instance.
     */
    void* object;
    void  (*delete)               (void* self);
} IInterceptFilter;

#endif

/*
 * End of iintercept_filter.h
 */

