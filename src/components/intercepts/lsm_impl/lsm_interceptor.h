/*
 * lsm_interceptor.h
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
#ifndef H_LSMINTERCEPTOR
#define H_LSMINTERCEPTOR

#include <asm/atomic.h>
#include <asm/ptrace.h>
#include <asm/semaphore.h>

#include "common/bool.h"
#define TALPA_SUBSYS "lsm"
#include "common/talpa.h"
#include "common/locking.h"
#include "interception/iinterceptor.h"
#include "intercept_processing/iintercept_processor.h"
#include "configurator/iconfigurable.h"
#include "configurator/pod_configuration_element.h"
#include "components/services/linux_filesystem_impl/linux_filesystem_factoryimpl.h"

#define LSM_CFGDATASIZE     (16)
#define LSM_OPSCFGDATASIZE  (64)



typedef struct {
    char    name[LSM_CFGDATASIZE];
    char    value[LSM_CFGDATASIZE];
} LSMStatusConfigData;

typedef struct {
    char    name[LSM_CFGDATASIZE];
    char    value[LSM_OPSCFGDATASIZE];
} LSMOpsConfigData;

typedef struct tag_LSMInterceptor
{
    IInterceptor                i_IInterceptor;
    IConfigurable               i_IConfigurable;
    void                        (*delete)(struct tag_LSMInterceptor* object);

    bool                        mSecondary;
    bool                        mInitialized;
    atomic_t                    mUseCnt;
    wait_queue_head_t           mUnload;
    talpa_mutex_t               mSemaphore;
    unsigned int                mInterceptMask;
    unsigned int                mHookingMask;
    IInterceptProcessor*        mTargetProcessor;
    PODConfigurationElement     mConfig[3];
    LSMStatusConfigData         mConfigData;
    LSMOpsConfigData            mOpsConfigData;
    LinuxFilesystemFactoryImpl* mLinuxFilesystemFactory;
} LSMInterceptor;

/*
 * Object Creators.
 */

LSMInterceptor* newLSMInterceptor(void);


#endif
