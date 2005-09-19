/*
 * filesystem_inclusion_processor.h
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
#ifndef H_FILESYSTEMINCLUSIONPROCESSOR
#define H_FILESYSTEMINCLUSIONPROCESSOR

#include <linux/limits.h>

#include "common/locking.h"
#include "intercept_filters/iintercept_filter.h"
#include "configurator/iconfigurable.h"

#define CFGDATASIZE      (16)

typedef struct {
    char    name[CFGDATASIZE];
    char    value[CFGDATASIZE];
} FSIPStateConfigData;

typedef struct {
    char    name[CFGDATASIZE];
    char    value[PATH_MAX];
} FSIPPathConfigData;

typedef struct tag_FilesystemInclusionProcessor
{
    IInterceptFilter            i_IInterceptFilter;
    IConfigurable               i_IConfigurable;
    void                        (*delete)(struct tag_FilesystemInclusionProcessor* object);
    void                        (*setPath)(void* self, const char* path);
    talpa_rw_lock_t             mConfigLock;
    bool                        mEnabled;
    char                        mPath[PATH_MAX];
    unsigned int                mPathLen;
    PODConfigurationElement     mConfig[3];
    FSIPStateConfigData         mStateConfigData[1];
    FSIPPathConfigData          mPathConfigData[1];
} FilesystemInclusionProcessor;

/*
 * Object Creators.
 */
FilesystemInclusionProcessor* newFilesystemInclusionProcessor(void);


#endif

/*
 * End of filesystem_inclusion_processor.h
 */

