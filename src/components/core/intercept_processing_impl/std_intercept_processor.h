/*
 * std_intercept_processor.h
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
#ifndef H_STDINTERCEPTPROCESSOR
#define H_STDINTERCEPTPROCESSOR

#include <asm/atomic.h>

#include "common/list.h"
#include "intercept_processing/iintercept_processor.h"
#include "configurator/iconfigurable.h"

#define STDINTPROC_CFGDATASIZE      (16)

typedef struct
{
    talpa_list_head     list;
    IInterceptFilter*   filter;
} FilterEntry;

typedef struct {
    char    name[STDINTPROC_CFGDATASIZE];
    char    value[STDINTPROC_CFGDATASIZE];
} StdIntProcConfigData;

typedef struct tag_StandardInterceptProcessor
{
    IInterceptProcessor         i_IInterceptProcessor;
    IConfigurable               i_IConfigurable;
    void                        (*delete)(struct tag_StandardInterceptProcessor* object);

    talpa_list_head             mEvaluationActions;
    talpa_list_head             mAllowActions;
    talpa_list_head             mDenyActions;
    atomic_t                    mNumConsecutiveTimeouts;
    PODConfigurationElement     mConfig[2];
    StdIntProcConfigData        mConfigData;
} StandardInterceptProcessor;

/*
 * Object Creators.
 */
StandardInterceptProcessor* newStandardInterceptProcessor(void);


#endif

/*
 * End of std_intercept_processor.h
 */

