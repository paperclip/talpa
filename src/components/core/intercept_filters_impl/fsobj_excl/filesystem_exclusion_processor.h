/*
 * filesystem_exclusion_processor.h
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
#ifndef H_FILESYSTEMEXCLUSIONPROCESSOR
#define H_FILESYSTEMEXCLUSIONPROCESSOR

#include <linux/limits.h>

#include "common/locking.h"
#include "common/list.h"
#include "intercept_filters/iintercept_filter.h"
#include "configurator/iconfigurable.h"

#define FSEXCPROC_CFGDATASIZE       (16)
#define FSEXCPROC_FSCFGDATASIZE     (128)
#define FSEXCPROC_SPECCFGDATASIZE   (64)

typedef struct {
    char    name[FSEXCPROC_CFGDATASIZE];
    char    value[FSEXCPROC_CFGDATASIZE];
} FSEPStateConfigData;

typedef struct {
    char    name[FSEXCPROC_CFGDATASIZE];
    char    value[PATH_MAX];
} FSEPPathConfigData;

typedef struct {
    char    name[FSEXCPROC_CFGDATASIZE];
    char    value[FSEXCPROC_FSCFGDATASIZE];
} FSEPFSConfigData;

typedef struct {
    char    name[FSEXCPROC_CFGDATASIZE];
    char    value[FSEXCPROC_SPECCFGDATASIZE];
} FSEPSpecialConfigData;


typedef struct
{
    talpa_list_head head;
    char*           value;
    unsigned int    len;
} FSEPObject;


typedef struct tag_FilesystemExclusionProcessor
{
    IInterceptFilter            i_IInterceptFilter;
    IConfigurable               i_IConfigurable;
    void                        (*delete)(struct tag_FilesystemExclusionProcessor* object);
    talpa_rcu_lock_t            mConfigLock;
    talpa_mutex_t               mConfigSerialize;
    bool                        mEnabled;
    talpa_list_head             mPaths;
    talpa_list_head             mFilesystems;
    talpa_list_head             mMountPaths;
    talpa_list_head             mMountFilesystems;
    unsigned int                mSpecialsMask;
    PODConfigurationElement     mConfig[7];
    FSEPStateConfigData         mStateConfigData;
    FSEPPathConfigData          mPathConfigData;
    FSEPFSConfigData            mFSConfigData;
    FSEPSpecialConfigData       mSpecialConfigData;
    FSEPPathConfigData          mMountPathConfigData;
    FSEPFSConfigData            mMountFSConfigData;
    char*                       mPathsSet;
    char*                       mFilesystemsSet;
    char*                       mMountPathsSet;
    char*                       mMountFilesystemsSet;
} FilesystemExclusionProcessor;

/*
 * Object Creators.
 */
FilesystemExclusionProcessor* newFilesystemExclusionProcessor(void);


#endif

/*
 * End of filesystem_exclusion_processor.h
 */

