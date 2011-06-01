/*
 * process_exclusion.h
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
#ifndef H_PROCESSEXCLUSIONPROCESSOR
#define H_PROCESSEXCLUSIONPROCESSOR

#include "common/locking.h"
#include "common/list.h"
#include "intercept_filters/iintercept_filter.h"
#include "process_excluder/iprocess_excluder.h"
#include "configurator/iconfigurable.h"

/*
 * Configuration structures
 */


#define PROCEXCL_CFGDATASIZE      (16)

typedef struct {
    char    name[PROCEXCL_CFGDATASIZE];
    char    value[PROCEXCL_CFGDATASIZE];
} ProcExclConfigData;


typedef struct tag_ProcessExclusionProcessor
{
    IInterceptFilter          i_IInterceptFilter;
    IProcessExcluder          i_IProcessExcluder;
    IConfigurable             i_IConfigurable;
    void                      (*delete)(struct tag_ProcessExclusionProcessor* object);
    talpa_mutex_t             mConfigSerialize;
    bool                      mEnabled;

    talpa_rcu_lock_t          mExcludedLock;
    talpa_list_head           mExcluded;

    PODConfigurationElement   mConfig[2];
    ProcExclConfigData        mStateConfigData;
} ProcessExclusionProcessor;

/*
 * Object Creators.
 */
ProcessExclusionProcessor* newProcessExclusionProcessor(void);



#endif

/*
 * End of process_exclusion.h
 */

