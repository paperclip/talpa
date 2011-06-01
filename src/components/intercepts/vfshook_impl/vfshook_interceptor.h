/*
 * vfshook_interceptor.h
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

#ifndef H_VFSHOOKINTERCEPTOR
#define H_VFSHOOKINTERCEPTOR

#include <asm/atomic.h>
#include <linux/fs.h>

#include "common/bool.h"
#define TALPA_SUBSYS "vfshook"
#include "common/talpa.h"
#include "common/locking.h"
#include "common/list.h"
#include "interception/iinterceptor.h"
#include "intercept_processing/iintercept_processor.h"
#include "configurator/iconfigurable.h"
#include "configurator/pod_configuration_element.h"
#include "components/services/linux_filesystem_impl/linux_filesystem_factoryimpl.h"
#include "components/services/linux_filesystem_impl/linux_systemroot.h"
#include "platforms/linux/talpa_syscallhook.h"

#define VFSHOOK_CFGDATASIZE     (16)
#define VFSHOOK_OPSCFGDATASIZE  (64)
#define VFSHOOK_FSCFGDATASIZE   (128)

typedef struct {
    char    name[VFSHOOK_CFGDATASIZE];
    char    value[VFSHOOK_CFGDATASIZE];
} VFSHookStatusConfigData;

typedef struct {
    char    name[VFSHOOK_CFGDATASIZE];
    char    value[VFSHOOK_OPSCFGDATASIZE];
} VFSHookOpsConfigData;

typedef struct {
    char    name[VFSHOOK_CFGDATASIZE];
    char    value[VFSHOOK_FSCFGDATASIZE];
} VFSHookFSConfigData;

typedef struct
{
    talpa_list_head head;
    char*           value;
    unsigned int    len;
    bool            protected;
} VFSHookObject;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,15)
 /* Got the struct namei->intent.open.file member */
#define TALPA_HAVE_INTENT
#else
#undef TALPA_HAVE_INTENT
#endif

/* Adjust as appropriate */
#if defined(CONFIG_NFS_V4) && defined(TALPA_HAVE_INTENT)
#define TALPA_HOOK_D_OPS
#endif


struct patchedFilesystem
{
    talpa_list_head         head;
    atomic_t                usecnt; /* How many mountpoints are patched with this record */
    atomic_t                refcnt; /* How many hook functions (+1 for usecnt > 0) are currently using this patch */
    struct file_system_type *fstype;
    talpa_simple_lock_t     lock; /* Held when modifying any stored pointers */
    struct inode_operations *i_ops;
    struct file_operations  *f_ops;
#ifdef TALPA_HAS_SMBFS
    struct file_operations  *sf_ops; /* smbfs file_operations */
#endif
    int                     (*open)(struct inode *, struct file *);
    int                     (*release)(struct inode *, struct file *);
#ifdef TALPA_HAS_SMBFS
  #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
    long                    (*ioctl)(struct file *filp, unsigned int cmd, unsigned long arg);
  #else
    int                     (*ioctl)(struct inode *inode, struct file *filp, unsigned int cmd, unsigned long arg);
  #endif
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
    int                     (*create)(struct inode *,struct dentry *,int, struct nameidata *);
    struct dentry*          (*lookup)(struct inode *,struct dentry *, struct nameidata *);
#else
    int                     (*create)(struct inode *,struct dentry *,int);
    struct dentry*          (*lookup)(struct inode *,struct dentry *);
#endif
#ifdef TALPA_HOOK_D_OPS
    struct dentry_operations *d_ops;
    int                     (*d_revalidate)(struct dentry *, struct nameidata *);
#endif
    bool                    mAlwaysHookLookup;
    bool                    mCreatePatched;
    bool                    mIoctlPatched;
    bool                    mHookDOps;
};

typedef struct tag_VFSHookInterceptor
{
    IInterceptor                    i_IInterceptor;
    IConfigurable                   i_IConfigurable;
    void                            (*delete)(struct tag_VFSHookInterceptor* object);

    IInterceptProcessor*            mTargetProcessor;
    LinuxFilesystemFactoryImpl*     mLinuxFilesystemFactory;
    LinuxSystemRoot*                mLinuxSystemRoot;
    char*                           mGoodFilesystemsSet;
    char*                           mSkipFilesystemsSet;
    char*                           mNoScanFilesystemsSet;
    char*                           mPatchListSet;

    unsigned int                    mInterceptMask;
    unsigned int                    mHookingMask;
    atomic_t                        mUseCnt;
    wait_queue_head_t               mUnload;
    talpa_mutex_t                   mSemaphore;
    talpa_rcu_lock_t                mPatchLock;
    talpa_list_head                 mPatches;
    talpa_rcu_lock_t                mListLock;
    talpa_list_head                 mGoodFilesystems;
    talpa_list_head                 mSkipFilesystems;
    talpa_list_head                 mNoScanFilesystems;
    PODConfigurationElement         mConfig[7];
    VFSHookStatusConfigData         mConfigData;
    VFSHookOpsConfigData            mOpsConfigData;
    VFSHookFSConfigData             mGoodListConfigData;
    VFSHookFSConfigData             mSkipListConfigData;
    VFSHookFSConfigData             mNoScanConfigData;
    VFSHookFSConfigData             mPatchConfigData;
    struct talpa_syscall_operations mSyscallOps;
    bool                            mInitialized;
} VFSHookInterceptor;

/*
 * Object Creators.
 */
VFSHookInterceptor* newVFSHookInterceptor(void);


#endif
