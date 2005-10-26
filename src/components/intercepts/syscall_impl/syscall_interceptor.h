/*
 * syscall_interceptor.h
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

#ifndef H_SYSCALLINTERCEPTOR
#define H_SYSCALLINTERCEPTOR

#include "common/bool.h"
#define TALPA_SUBSYS "syscall"
#include "common/talpa.h"
#include "common/locking.h"
#include "interception/iinterceptor.h"
#include "intercept_processing/iintercept_processor.h"
#include "configurator/iconfigurable.h"
#include "configurator/pod_configuration_element.h"
#include "components/services/linux_filesystem_impl/linux_filesystem_factoryimpl.h"
#include "platforms/linux/talpa_syscallhook.h"

#define SYSCALL_CFGDATASIZE     (16)
#define SYSCALL_OPSCFGDATASIZE  (64)

typedef struct {
    char    name[SYSCALL_CFGDATASIZE];
    char    value[SYSCALL_CFGDATASIZE];
} SyscallStatusConfigData;

typedef struct {
    char    name[SYSCALL_CFGDATASIZE];
    char    value[SYSCALL_OPSCFGDATASIZE];
} SyscallOpsConfigData;

typedef struct tag_SyscallInterceptor
{
    IInterceptor                    i_IInterceptor;
    IConfigurable                   i_IConfigurable;
    void                            (*delete)(struct tag_SyscallInterceptor* object);

    bool                            mInitialized;
    talpa_mutex_t                   mSemaphore;
    bool                            mInterceptEnabled;
    unsigned int                    mHookingMask;
    IInterceptProcessor*            mTargetProcessor;
    PODConfigurationElement         mConfig[3];
    SyscallStatusConfigData         mConfigData;
    SyscallOpsConfigData            mOpsConfigData;
    LinuxFilesystemFactoryImpl*     mLinuxFilesystemFactory;
    int                             (*syscallhook_register)(struct talpa_syscall_operations* ops);
    void                            (*syscallhook_unregister)(struct talpa_syscall_operations* ops);
    struct talpa_syscall_operations mSyscallOps;
} SyscallInterceptor;

/*
 * Object Creators.
 */
SyscallInterceptor* newSyscallInterceptor(void);


#endif
