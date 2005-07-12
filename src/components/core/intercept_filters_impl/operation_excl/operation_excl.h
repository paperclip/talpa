/*
 * operation_excl.h
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
#ifndef H_OPERATIONEXCLUSIONPROCESSOR
#define H_OPERATIONEXCLUSIONPROCESSOR


#include "common/locking.h"
#include "intercept_filters/iintercept_filter.h"
#include "configurator/iconfigurable.h"

#define OPERATIONEXCLUSIONPROCESSOR_CFGDATASIZE      (sizeof(char) * 16)

typedef struct {
    char    name[OPERATIONEXCLUSIONPROCESSOR_CFGDATASIZE];
    char    value[OPERATIONEXCLUSIONPROCESSOR_CFGDATASIZE];
} OperationExclusionProcessorConfigData;

typedef struct tag_OperationExclusionProcessor
{
    IInterceptFilter                        i_IInterceptFilter;
    IConfigurable                           i_IConfigurable;
    void                                    (*delete)(struct tag_OperationExclusionProcessor* object);
    bool                                    mEnabled;
    bool                                    mOnlyBlockDev;
    talpa_mutex_t                           mConfigSerialize;
    PODConfigurationElement                 mConfig[3];
    OperationExclusionProcessorConfigData   mConfigStatus[1];
    OperationExclusionProcessorConfigData   mConfigOnlyBlockDev[1];
} OperationExclusionProcessor;

/*
 * Object Creators.
 */
OperationExclusionProcessor* newOperationExclusionProcessor(void);


#endif

/*
 * End of operation_excl.h
 */

