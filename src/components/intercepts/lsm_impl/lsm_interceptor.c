/*
 * lsm_interceptor.c
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

#include <linux/kernel.h>
#define __NO_VERSION__
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/smp_lock.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/unistd.h>
#include <linux/binfmts.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <asm/hardirq.h>
#include <asm/system.h>
#include <asm/mman.h>

#include "lsm_interceptor.h"
#include "app_ctrl/iportability_app_ctrl.h"
#include "filesystem/ifile_info.h"
#include "platform/talpa_capability.h"
#include "platforms/linux/alloc.h"
#include "platforms/linux/glue.h"

/* define this to use inode_permission hook, undef it to use file_permission */
#define INODE_PERMISSION


/*
 * Forward declare implementation methods.
 */

static bool enable(void* self);
static void disable(void* self);
static bool isEnabled(const void* self);
static void addInterceptProcessor(void* self, IInterceptProcessor* processor);
static IInterceptProcessor* interceptProcessor(const void* self);
static const char* configName(const void* self);
static const PODConfigurationElement* allConfig(const void* self);
static const char* config(const void* self, const char* name);
static void setConfig(void* self, const char* name, const char* value);
static void deleteLSMInterceptor(struct tag_LSMInterceptor* object);

static void constructSpecialSet(void* self);

/*
 * Constants
 */
#define CFG_STATUS          "status"
#define CFG_OPS             "ops"
#define CFG_VALUE_ENABLED   "enabled"
#define CFG_VALUE_DISABLED  "disabled"
#define CFG_ACTION_ENABLE   "enable"
#define CFG_ACTION_DISABLE  "disable"
#define CFG_VALUE_DUMMY     "(empty)"

#define HOOK_OPEN       0x01
#define HOOK_CLOSE      0x02
#define HOOK_EXEC       0x04
#define HOOK_MOUNT      0x10
#define HOOK_UMOUNT     0x20

#define HOOK_DEFAULT (HOOK_OPEN | HOOK_CLOSE | HOOK_EXEC | HOOK_MOUNT | HOOK_UMOUNT)

/*
 * Singleton object.
 */

static LSMInterceptor GL_object =
    {
        {
            enable,
            disable,
            isEnabled,
            addInterceptProcessor,
            interceptProcessor,
            &GL_object,
            (void (*)(void*))deleteLSMInterceptor
        },
        {
            configName,
            allConfig,
            config,
            setConfig,
            &GL_object,
            (void (*)(void*))deleteLSMInterceptor
        },
        deleteLSMInterceptor,
        false,
        false,
        ATOMIC_INIT(0),
        { },
        TALPA_STATIC_MUTEX(GL_object.mSemaphore),
        0,
        HOOK_DEFAULT,
        NULL,
        {
            {GL_object.mConfigData.name, GL_object.mConfigData.value, LSM_CFGDATASIZE, true, true },
            {GL_object.mOpsConfigData.name, GL_object.mOpsConfigData.value, LSM_OPSCFGDATASIZE, true, false },
            {NULL, NULL, 0, false, false }
        },
        { CFG_STATUS, CFG_VALUE_DISABLED },
        { CFG_OPS, CFG_VALUE_DUMMY },
        NULL
};

#define this    ((LSMInterceptor*)self)

static inline int examineFile(const void* self, EFilesystemOperation op, struct file* file, bool clonefile)
{
    int decision = 0;
    IFileInfo *pFInfo;


    /* We can't use a file object without a dentry or inode */
    if ( ( file->f_dentry == NULL ) || ( file->f_dentry->d_inode == NULL ) )
    {
        return 0;
    }

    /* First check with the examineInode method */
    decision = this->mTargetProcessor->examineInode(this->mTargetProcessor, op, kdev_t_to_nr(inode_dev(file->f_dentry->d_inode)), file->f_dentry->d_inode->i_ino);

    if ( likely ( decision == 0 ) )
    {
        return 0;
    }
    else if ( decision != -EAGAIN )
    {
        return decision;
    }

    /* Make sure our open and close attempts while examining will be excluded */
    current->flags |= PF_TALPA_INTERNAL;

    pFInfo = this->mLinuxFilesystemFactory->i_IFilesystemFactory.newFileInfoFromFile(this->mLinuxFilesystemFactory, op, file);

    if ( likely(pFInfo != NULL) )
    {
        IFile *pFile = NULL;
#ifdef TALPA_SAME_FILE
        if ( clonefile )
        {
            pFile = GL_object.mLinuxFilesystemFactory->i_IFilesystemFactory.cloneFile(GL_object.mLinuxFilesystemFactory, file);
        }
#endif
        decision = this->mTargetProcessor->examineFileInfo(this->mTargetProcessor, pFInfo, pFile);
#ifdef TALPA_SAME_FILE
        if ( likely(pFile != NULL) )
        {
            pFile->delete(pFile);
        }
#endif
        pFInfo->delete(pFInfo);
    }

    /* Restore normal process examination */
    current->flags &= ~PF_TALPA_INTERNAL;

    return decision;
}

static inline int examineDirectoryEntry(const void* self, EFilesystemOperation op, struct dentry* dentry, struct vfsmount* mnt, int flags, int mode)
{
    int decision = 0;
    IFileInfo *pFInfo;


    /* First check with the examineInode method */
    decision = this->mTargetProcessor->examineInode(this->mTargetProcessor, op, kdev_t_to_nr(inode_dev(dentry->d_inode)), dentry->d_inode->i_ino);

    if ( likely ( decision == 0 ) )
    {
        return 0;
    }
    else if ( decision != -EAGAIN )
    {
        return decision;
    }

    /* Make sure our open and close attempts while examining will be excluded */
    current->flags |= PF_TALPA_INTERNAL;

    pFInfo = this->mLinuxFilesystemFactory->i_IFilesystemFactory.newFileInfoFromDirectoryEntry(this->mLinuxFilesystemFactory, op, dentry, mnt, flags, mode);

    if ( likely(pFInfo != NULL) )
    {
        decision = this->mTargetProcessor->examineFileInfo(this->mTargetProcessor, pFInfo, NULL);
        pFInfo->delete(pFInfo);
    }

    /* Restore normal process examination */
    current->flags &= ~PF_TALPA_INTERNAL;

    return decision;
}

static inline int examineInode(const void* self, EFilesystemOperation op, struct inode* inode, int flags)
{
    int decision = 0;
    IFileInfo *pFInfo;


    /* Make sure our open and close attempts while examining will be excluded */
    current->flags |= PF_TALPA_INTERNAL;

    pFInfo = this->mLinuxFilesystemFactory->i_IFilesystemFactory.newFileInfoFromInode(this->mLinuxFilesystemFactory, op, inode, flags);

    if ( likely(pFInfo != NULL) )
    {
        decision = this->mTargetProcessor->runAllowChain(this->mTargetProcessor, pFInfo);
        pFInfo->delete(pFInfo);
    }

    /* Restore normal process examination */
    current->flags &= ~PF_TALPA_INTERNAL;

    return decision;
}

static inline int examineFilesystem(const void* self, EFilesystemOperation op, char* dev, char* dir, char* fstype)
{
    int decision = 0;
    IFilesystemInfo *pFSInfo = this->mLinuxFilesystemFactory->i_IFilesystemFactory.newFilesystemInfo(this->mLinuxFilesystemFactory, op, dev, dir, fstype);

    if ( likely(pFSInfo != NULL) )
    {
        decision = this->mTargetProcessor->examineFilesystemInfo(this->mTargetProcessor, pFSInfo);
        pFSInfo->delete(pFSInfo);
    }

    return decision;
}

#define hookEntry() atomic_inc(&GL_object.mUseCnt)

#define hookExit() \
{ \
    if ( unlikely( atomic_dec_and_test(&GL_object.mUseCnt) !=  0 ) ) \
    { \
        wake_up(&GL_object.mUnload); \
    } \
\
    return; \
}

#define hookExitRv(ret) \
{ \
    if ( unlikely( atomic_dec_and_test(&GL_object.mUseCnt) !=  0 ) ) \
    { \
        wake_up(&GL_object.mUnload); \
    } \
    return ret; \
}

#ifdef INODE_PERMISSION

static inline int talpa_inode_permission(struct inode *inode, int mask, struct nameidata *nd)
{
    int flags;
    int decision;

    flags = 0;

    /* Ignore lookups */
    if ( likely( mask == MAY_EXEC ) )
    {
        return 0;
    }

    /* Ignore directory lookups before inode_create */
    if ( unlikely( mask == ( MAY_EXEC | MAY_WRITE ) ) )
    {
        return 0;
    }

    if ( unlikely( !nd ) )
    {
        return 0;
    }

    if ( unlikely( !(GL_object.mInterceptMask & HOOK_OPEN) ) )
    {
        return 0;
    }

    /* Do not schedule for examination if this is our internal open */
    if ( current->flags & PF_TALPA_INTERNAL )
    {
        return 0;
    }

    if ( mask & MAY_APPEND )
    {
        flags |= O_APPEND;
    }

    if ( ( mask & ( MAY_WRITE | MAY_READ ) ) == ( MAY_WRITE | MAY_READ ) )
    {
        flags |= O_RDWR;
    }
    else if ( mask & MAY_WRITE )
    {
        flags |= O_WRONLY;
    }

    /* FIXME: Is it correct to assume that when nd->flags == 0 the kernel
        is doing an "operation on internally mounted fs"? It works well
        in practice and I haven't found a problem with it. */
    if ( unlikely( !nd->flags ) )
    {
        dbg("operation on kern_mount fs");
        return 0;
    }

    decision = examineDirectoryEntry(&GL_object, EFS_Open, nd->dentry, nd->mnt, flags, -1);

    return decision;
}

static int talpa_lsm_inode_permission(struct inode *inode, int mask, struct nameidata *nd)
{
    int decision;

    hookEntry();

    decision = talpa_inode_permission(inode, mask, nd);

    hookExitRv(decision);
}

static int talpa_cap_inode_permission(struct inode *inode, int mask, struct nameidata *nd)
{
    int decision;

    decision = talpa_inode_permission(inode, mask, nd);

    return decision;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
static inline int talpa_inode_init_security(struct inode *inode, struct inode *dir, char **name, void **value, size_t *len)
{
    if ( likely( GL_object.mInterceptMask & HOOK_OPEN) )
    {
        examineInode(&GL_object, EFS_Open, inode, O_CREAT | O_EXCL);
    }

    return -EOPNOTSUPP;
}

static int talpa_lsm_inode_init_security(struct inode *inode, struct inode *dir, char **name, void **value, size_t *len)
{
    int decision;

    hookEntry();

    decision = talpa_inode_init_security(inode, dir, name, value, len);

    hookExitRv(decision);
}

static int talpa_cap_inode_init_security(struct inode *inode, struct inode *dir, char **name, void **value, size_t *len)
{
    return talpa_inode_init_security(inode, dir, name, value, len);
}
#else
static inline void talpa_inode_post_create(struct inode *dir, struct dentry *dentry, int mode)
{
    if ( likely( GL_object.mInterceptMask & HOOK_OPEN) )
    {
        examineInode(&GL_object, EFS_Open, dentry->d_inode, O_CREAT | O_EXCL);
    }
}

static void talpa_lsm_inode_post_create(struct inode *dir, struct dentry *dentry, int mode)
{
    hookEntry();

    talpa_inode_post_create(dir, dentry, mode);

    hookExit();
}

static void talpa_cap_inode_post_create(struct inode *dir, struct dentry *dentry, int mode)
{
    talpa_inode_post_create(dir, dentry, mode);
}
#endif

#else /* INODE_PERMISSION */

static int talpa_file_alloc_security(struct file *file)
{
    hookEntry();

    file->f_security = 0;

    /* Do not schedule for examination if this is our internal open
        and if we are not enabled */
    if ( likely( GL_object.mInterceptMask && !(current->flags & PF_TALPA_INTERNAL) ) )
    {
        file->f_security = ERR_PTR(-EAGAIN);
    }

    hookExitRv(0);
}

static int talpa_file_permission(struct file *file, int mask)
{
    int decision;
    EFilesystemOperation op;

    hookEntry();

    decision = PTR_ERR(file->f_security);

    if ( likely(decision != -EAGAIN) )
    {
        hookExitRv(decision);
    }

    op = EFS_Open;

    if ( mask & MAY_EXEC )
    {
        if ( unlikely( !(GL_object.mInterceptMask & HOOK_EXEC) ) )
        {
            hookExitRv(0);
        }
        op = EFS_Exec;
    }

    if ( unlikely( !(GL_object.mInterceptMask & HOOK_OPEN) ) )
    {
        hookExitRv(0);
    }

    decision = examineFile(&GL_object, op, file, true);

    file->f_security = ERR_PTR(decision);

    hookExitRv(decision);
}

static inline int talpa_file_mmap(struct file * file, unsigned long prot, unsigned long flags)
{
    int decision;
    EFilesystemOperation op;

    hookEntry();

    /* Anonymous memory? */
    if ( unlikely(!file) )
    {
        hookExitRv(0);
    }

    decision = PTR_ERR(file->f_security);

    if ( likely(decision != -EAGAIN) )
    {
        hookExitRv(decision);
    }

    /* Private write-only segment? */
    if ( unlikely( !( prot & (PROT_READ | PROT_EXEC) ) && ( flags & MAP_PRIVATE ) ) )
    {
        hookExitRv(0);
    }

    op = EFS_Open;

    if ( prot & PROT_EXEC )
    {
        if ( unlikely( !(GL_object.mInterceptMask & HOOK_EXEC) ) )
        {
            hookExitRv(0);
        }
        op = EFS_Exec;
    }

    if ( unlikely( !(GL_object.mInterceptMask & HOOK_OPEN) ) )
    {
        hookExitRv(0);
    }

    decision = examineFile(&GL_object, op, file, true);

    file->f_security = ERR_PTR(decision);

    hookExitRv(decision);
}

#endif /* INODE_PERMISSION */

static inline int talpa_bprm_check_security(struct linux_binprm* bprm)
{
    int ret;


    if ( unlikely( !(GL_object.mInterceptMask & HOOK_EXEC) ) )
    {
        return 0;
    }

    ret = examineFile(&GL_object, EFS_Exec, bprm->file, true);

    return ret;
}

static int talpa_lsm_bprm_check_security(struct linux_binprm* bprm)
{
    int decision;


    hookEntry();

    decision = talpa_bprm_check_security(bprm);

    hookExitRv(decision);
}

static int talpa_cap_bprm_check_security(struct linux_binprm* bprm)
{
    int decision;


    decision = talpa_bprm_check_security(bprm);

    return decision;
}

static inline void talpa_file_free_security(struct file *file)
{
    if ( unlikely( !(GL_object.mInterceptMask & HOOK_CLOSE) ) )
    {
        return;
    }

    /* Do not examine if this is our internal close */
    if ( current->flags & PF_TALPA_INTERNAL )
    {
        return;
    }

    examineFile(&GL_object, EFS_Close, file, false);

    return;
}

static void talpa_lsm_file_free_security(struct file *file)
{
    hookEntry();

    talpa_file_free_security(file);

    hookExit();
}

static void talpa_cap_file_free_security(struct file *file)
{
    talpa_file_free_security(file);
}

static inline int talpa_sb_mount(char *dev_name, struct nameidata *nd, char *type, unsigned long flags, void *data)
{
    char *mpath;
    size_t path_size = 0;
    char *mountpoint;
    int decision;


    decision = 0;

    if ( unlikely( !(GL_object.mInterceptMask & HOOK_MOUNT) ) )
    {
        return 0;
    }

    mpath = talpa_alloc_path(&path_size);
    if ( unlikely(mpath == NULL) )
    {
        return -ENOMEM;
    }

    mountpoint = d_path(nd->dentry, nd->mnt, mpath, path_size);
    if ( unlikely( IS_ERR(mountpoint) != 0 ) )
    {
        mountpoint = NULL;
    }
    decision = examineFilesystem(&GL_object, EFS_Mount, dev_name, mountpoint, type);

    talpa_free_path(mpath);

    return decision;
}

static int talpa_lsm_sb_mount(char *dev_name, struct nameidata *nd, char *type, unsigned long flags, void *data)
{
    int decision;


    hookEntry();

    decision = talpa_sb_mount(dev_name, nd, type, flags, data);

    hookExitRv(decision);
}

static int talpa_cap_sb_mount(char *dev_name, struct nameidata *nd, char *type, unsigned long flags, void *data)
{
    int decision;


    decision = talpa_sb_mount(dev_name, nd, type, flags, data);

    return decision;
}

static inline int talpa_sb_umount(struct vfsmount *mnt, int flags)
{
    char *mpath;
    size_t path_size = 0;
    char *mountpoint;


    if ( unlikely( !(GL_object.mInterceptMask & HOOK_UMOUNT) ) )
    {
        return 0;
    }

    mpath = talpa_alloc_path(&path_size);
    if ( likely(mpath != NULL) )
    {
        mountpoint = d_path(mnt->mnt_mountpoint, mnt->mnt_parent, mpath, path_size);
        if ( unlikely( IS_ERR(mountpoint) != 0 ) )
        {
            mountpoint = NULL;
        }
        examineFilesystem(&GL_object, EFS_Umount, NULL, mountpoint, NULL);
        talpa_free_path(mpath);
    }

    return 0;
}

static int talpa_lsm_sb_umount(struct vfsmount *mnt, int flags)
{
    hookEntry();

    talpa_sb_umount(mnt, flags);

    hookExitRv(0);

}

static int talpa_cap_sb_umount(struct vfsmount *mnt, int flags)
{
    return talpa_sb_umount(mnt, flags);
}

static struct security_operations interceptor_ops_plain = {
#ifdef INODE_PERMISSION
    .inode_permission =         talpa_lsm_inode_permission,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
    .inode_init_security =      talpa_lsm_inode_init_security,
#else
    .inode_post_create =        talpa_lsm_inode_post_create,
#endif
#else
    .file_alloc_security =      talpa_file_alloc_security,
    .file_permission =          talpa_file_permission,
    .file_mmap =                talpa_file_mmap,
#endif
    .file_free_security =       talpa_lsm_file_free_security,
    .bprm_check_security =      talpa_lsm_bprm_check_security,
    .sb_mount =                 talpa_lsm_sb_mount,
    .sb_umount =                talpa_lsm_sb_umount,
};

static struct security_operations interceptor_ops_with_cap = {
/* Capabilities part is dynamically initialised from the
   constructor so that we do not depend on commoncap being
   present. The only exception are the two netlink hooks
   which are inlined from security.h on kernel <= 2.6.9 .*/

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,9)
    .netlink_send =             cap_netlink_send,
    .netlink_recv =             cap_netlink_recv,
#endif

/* Talpa part */
#ifdef INODE_PERMISSION
    .inode_permission =         talpa_lsm_inode_permission,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
    .inode_init_security =      talpa_lsm_inode_init_security,
#else
    .inode_post_create =        talpa_lsm_inode_post_create,
#endif
#else
    .file_alloc_security =      talpa_file_alloc_security,
    .file_permission =          talpa_file_permission,
    .file_mmap =                talpa_file_mmap,
#endif
    .file_free_security =       talpa_lsm_file_free_security,
    .bprm_check_security =      talpa_lsm_bprm_check_security,
    .sb_mount =                 talpa_lsm_sb_mount,
    .sb_umount =                talpa_lsm_sb_umount,
};

static struct talpa_capability_interceptor talpa_capability_ops = {
    .inode_permission =         talpa_cap_inode_permission,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
    .inode_init_security =      talpa_cap_inode_init_security,
#else
    .inode_post_create =        talpa_cap_inode_post_create,
#endif
    .file_free_security =       talpa_cap_file_free_security,
    .bprm_check_security =      talpa_cap_bprm_check_security,
    .sb_mount =                 talpa_cap_sb_mount,
    .sb_umount =                talpa_cap_sb_umount,
};

static char module_name_plain[] = "talpa-lsm";
static char module_name_capabilities[] = "talpa-lsm-capabilities";

static struct security_operations* interceptor_ops = &interceptor_ops_plain;
static char* module_name = module_name_plain;
static int capabilities = 0;

module_param(capabilities, int, 0400);
MODULE_PARM_DESC(capabilities, "register built-in default linux capabilities (default: 0 = no)");

static int (*capability_register)(struct talpa_capability_interceptor* interceptor);
static void (*capability_unregister)(struct talpa_capability_interceptor* interceptor);

/*
 * Object creation/destruction.
 */

static void putCapabilites(void)
{
    if ( interceptor_ops_with_cap.ptrace )
    {
        symbol_put(cap_ptrace);
    }
    if ( interceptor_ops_with_cap.capget )
    {
        symbol_put(cap_capget);
    }
    if ( interceptor_ops_with_cap.capset_check )
    {
        symbol_put(cap_capset_check);
    }
    if ( interceptor_ops_with_cap.capset_set )
    {
        symbol_put(cap_capset_set);
    }
    if ( interceptor_ops_with_cap.capable )
    {
        symbol_put(cap_capable);
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
    if ( interceptor_ops_with_cap.netlink_send )
    {
        symbol_put(cap_netlink_send);
    }
    if ( interceptor_ops_with_cap.netlink_recv )
    {
        symbol_put(cap_netlink_recv);
    }
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,6)) || defined TALPA_HAS_266_LSM
    if ( interceptor_ops_with_cap.bprm_apply_creds )
    {
        symbol_put(cap_bprm_apply_creds);
    }
#else
    if ( interceptor_ops_with_cap.bprm_compute_creds )
    {
        symbol_put(cap_bprm_compute_creds);
    }
#endif
    if ( interceptor_ops_with_cap.bprm_set_security )
    {
        symbol_put(cap_bprm_set_security);
    }
    if ( interceptor_ops_with_cap.bprm_secureexec )
    {
        symbol_put(cap_bprm_secureexec);
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,2)
    if ( interceptor_ops_with_cap.inode_setxattr )
    {
        symbol_put(cap_inode_setxattr);
    }
    if ( interceptor_ops_with_cap.inode_removexattr )
    {
        symbol_put(cap_inode_removexattr);
    }
#endif
    if ( interceptor_ops_with_cap.task_post_setuid )
    {
        symbol_put(cap_task_post_setuid);
    }
    if ( interceptor_ops_with_cap.task_reparent_to_init )
    {
        symbol_put(cap_task_reparent_to_init);
    }
    if ( interceptor_ops_with_cap.syslog )
    {
        symbol_put(cap_syslog);
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
    if ( interceptor_ops_with_cap.settime )
    {
        symbol_put(cap_settime);
    }
#endif
    if ( interceptor_ops_with_cap.vm_enough_memory )
    {
        symbol_put(cap_vm_enough_memory);
    }
}

static bool getCapabilities(void)
{
    interceptor_ops_with_cap.ptrace = symbol_get(cap_ptrace);
    if ( !interceptor_ops_with_cap.ptrace )
    {
        goto failed;
    }
    interceptor_ops_with_cap.capget = symbol_get(cap_capget);
    if ( !interceptor_ops_with_cap.capget )
    {
        goto failed;
    }
    interceptor_ops_with_cap.capset_check = symbol_get(cap_capset_check);
    if ( !interceptor_ops_with_cap.capset_check )
    {
        goto failed;
    }
    interceptor_ops_with_cap.capset_set = symbol_get(cap_capset_set);
    if ( !interceptor_ops_with_cap.capset_set )
    {
        goto failed;
    }
    interceptor_ops_with_cap.capable = symbol_get(cap_capable);
    if ( !interceptor_ops_with_cap.capable )
    {
        goto failed;
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
    interceptor_ops_with_cap.netlink_send = symbol_get(cap_netlink_send);
    if ( !interceptor_ops_with_cap.netlink_send )
    {
        goto failed;
    }
    interceptor_ops_with_cap.netlink_recv = symbol_get(cap_netlink_recv);
    if ( !interceptor_ops_with_cap.netlink_recv )
    {
        goto failed;
    }
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,6)) || defined TALPA_HAS_266_LSM
    interceptor_ops_with_cap.bprm_apply_creds = symbol_get(cap_bprm_apply_creds);
    if ( !interceptor_ops_with_cap.bprm_apply_creds )
    {
        goto failed;
    }
#else
    interceptor_ops_with_cap.bprm_compute_creds = symbol_get(cap_bprm_compute_creds);
    if ( !interceptor_ops_with_cap.bprm_compute_creds )
    {
        goto failed;
    }
#endif
    interceptor_ops_with_cap.bprm_set_security = symbol_get(cap_bprm_set_security);
    if ( !interceptor_ops_with_cap.bprm_set_security )
    {
        goto failed;
    }
    interceptor_ops_with_cap.bprm_secureexec = symbol_get(cap_bprm_secureexec);
    if ( !interceptor_ops_with_cap.bprm_secureexec )
    {
        goto failed;
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,2)
    interceptor_ops_with_cap.inode_setxattr = symbol_get(cap_inode_setxattr);
    if ( !interceptor_ops_with_cap.inode_setxattr )
    {
        goto failed;
    }
    interceptor_ops_with_cap.inode_removexattr = symbol_get(cap_inode_removexattr);
    if ( !interceptor_ops_with_cap.inode_removexattr )
    {
        goto failed;
    }
#endif
    interceptor_ops_with_cap.task_post_setuid = symbol_get(cap_task_post_setuid);
    if ( !interceptor_ops_with_cap.task_post_setuid )
    {
        goto failed;
    }
    interceptor_ops_with_cap.task_reparent_to_init = symbol_get(cap_task_reparent_to_init);
    if ( !interceptor_ops_with_cap.task_reparent_to_init )
    {
        goto failed;
    }
    interceptor_ops_with_cap.syslog = symbol_get(cap_syslog);
    if ( !interceptor_ops_with_cap.syslog )
    {
        goto failed;
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
    interceptor_ops_with_cap.settime = symbol_get(cap_settime);
    if ( !interceptor_ops_with_cap.settime )
    {
        goto failed;
    }
#endif
    interceptor_ops_with_cap.vm_enough_memory = symbol_get(cap_vm_enough_memory);
    if ( !interceptor_ops_with_cap.vm_enough_memory )
    {
        goto failed;
    }

    return true;

failed:

    putCapabilites();

    return false;
}

LSMInterceptor* newLSMInterceptor(void)
{
    talpa_mutex_lock(&GL_object.mSemaphore);

    if ( GL_object.mInitialized )
    {
        talpa_mutex_unlock(&GL_object.mSemaphore);
        err("Duplicate initialization attempted!");
        return NULL;
    }

    init_waitqueue_head(&GL_object.mUnload);

    /* Check if we can register with talpa_capability */
    capability_register = symbol_get(talpa_capability_register);
    capability_unregister = symbol_get(talpa_capability_unregister);
    if ( capability_register && capability_unregister )
    {
        if ( capabilities )
        {
            info("Registering with talpa-capability (will not activate built-in capabilities)");
        }
        else
        {
            info("Registering with talpa-capability");
        }

        if ( capability_register(&talpa_capability_ops) )
        {
            err("Failed to register with talpa-capability!");
            return NULL;
        }
    }
    else
    {
        if ( capabilities )
        {
            /* See if capabilities are available */
            if ( getCapabilities() )
            {
                info("Activating built-in default linux capabilities");
                module_name = module_name_capabilities;
                interceptor_ops = &interceptor_ops_with_cap;
            }
            else
            {
                warn("Failed to activate default linux capabilities");
            }
        }

        if ( register_security(interceptor_ops) )
        {
            if ( mod_reg_security(module_name, interceptor_ops) )
            {
                err("Failure registering security module!");
                return NULL;
            }
            info("Registered as secondary security module");
            GL_object.mSecondary = true;
        }
        else
        {
            info("Registered as primary security module");
        }
    }

    constructSpecialSet(&GL_object);
    GL_object.mLinuxFilesystemFactory = TALPA_Portability()->filesystemFactory()->object;

    GL_object.mInitialized = true;

    talpa_mutex_unlock(&GL_object.mSemaphore);

    return &GL_object;
}

static void deleteLSMInterceptor(struct tag_LSMInterceptor* object)
{
    dbg("destructor");

    talpa_mutex_lock(&object->mSemaphore);

    if ( !object->mInitialized )
    {
        talpa_mutex_unlock(&object->mSemaphore);
        err("Tried to delete before initializing!");
        return;
    }

    if ( object->mInterceptMask )
    {
        object->mInterceptMask = 0;
        strcpy(object->mConfigData.value, CFG_VALUE_DISABLED);
    }

    object->mLinuxFilesystemFactory = NULL;

    if ( capability_register )
    {
        capability_unregister(&talpa_capability_ops);
        symbol_put(talpa_capability_register);
        symbol_put(talpa_capability_unregister);
    }
    else
    {
        if ( object->mSecondary )
        {
            if ( mod_unreg_security(module_name, interceptor_ops) )
            {
                err("Failure unregistering security module!");
            }
        }
        else
        {
            if ( unregister_security(interceptor_ops) )
            {
                err("Failure unregistering security module!");
            }
        }

        if ( interceptor_ops == &interceptor_ops_with_cap )
        {
            putCapabilites();
        }
    }

    object->mInitialized = false;

    talpa_mutex_unlock(&object->mSemaphore);

    /* Now we must wait for users to stop using it */
    wait_event(object->mUnload, atomic_read(&object->mUseCnt) == 0);

    return;
}

/*
 * Hook functions
 */
#define catState(string, check, name) \
do \
{ \
    if ( this->mHookingMask & check ) \
    { \
        strcat(string, "+"); \
    } \
    else \
    { \
        strcat(string, "-"); \
    } \
    strcat(string, name); \
} \
while ( 0 )

static void constructSpecialSet(void* self)
{
    char* out = this->mOpsConfigData.value;

    *out = 0;

    catState(out, HOOK_OPEN, "open\n");
    catState(out, HOOK_CLOSE, "close\n");
    catState(out, HOOK_EXEC, "exec\n");
    catState(out, HOOK_MOUNT, "mount\n");
    catState(out, HOOK_UMOUNT, "umount\n");

    return;
}

#undef catState

static void doSpecialString(void* self, const char* value)
{
    unsigned long mask = 0;


    if ( strlen(value) >= 2 )
    {
        if ( !strcmp(&value[1], "open") )
        {
            mask = HOOK_OPEN;
        }
        else if ( !strcmp(&value[1], "close") )
        {
            mask = HOOK_CLOSE;
        }
        else if ( !strcmp(&value[1], "exec") )
        {
            mask = HOOK_EXEC;
        }
        else if ( !strcmp(&value[1], "mount") )
        {
            mask = HOOK_MOUNT;
        }
        else if ( !strcmp(&value[1], "umount") )
        {
            mask = HOOK_UMOUNT;
        }

        if ( value[0] == '+' )
        {
            this->mHookingMask |= mask;
        }
        else if ( value[0] == '-' )
        {
            this->mHookingMask &= ~(mask);
        }
    }

    constructSpecialSet(this);

    return;
}

static bool enable(void* self)
{
    if ( !this->mTargetProcessor )
    {
        err("No processor!");
        return false;
    }

    if ( !this->mInterceptMask && this->mHookingMask )
    {
        if ( try_module_get(THIS_MODULE) )
        {
            atomic_inc(&this->mUseCnt);
            this->mInterceptMask = this->mHookingMask;
            strcpy(this->mConfigData.value, CFG_VALUE_ENABLED);
            info("Enabled");
            return true;
        }
        else
        {
            warn("Failed to enable");
        }
    }

    return false;
}

static void disable(void* self)
{
    if (this->mInterceptMask)
    {
        this->mInterceptMask = 0;
        atomic_dec(&this->mUseCnt);
        strcpy(this->mConfigData.value, CFG_VALUE_DISABLED);
        module_put(THIS_MODULE);
        info("Disabled");
    }
    return;
}

static bool isEnabled(const void* self)
{
    return this->mInterceptMask?true:false;
}

static void addInterceptProcessor(void* self, IInterceptProcessor* processor)
{

    this->mTargetProcessor = processor;
    return;
}

static IInterceptProcessor* interceptProcessor(const void* self)
{
    return this->mTargetProcessor;
}

/*
 * IConfigurable.
 */
static const char* configName(const void* self)
{
    return "LSMInterceptor";
}

static const PODConfigurationElement* allConfig(const void* self)
{
    return this->mConfig;
}

static const char* config(const void* self, const char* name)
{
    PODConfigurationElement*    cfgElement;


    /*
     * Find the named item.
     */
    for (cfgElement = this->mConfig; cfgElement->name != NULL; cfgElement++)
    {
        if (strcmp(name, cfgElement->name) == 0)
        {
            break;
        }
    }

    /*
     * Return what was found else a null pointer.
     */
    if ( cfgElement->name )
    {
        return cfgElement->value;
    }
    return 0;
}

static void  setConfig(void* self, const char* name, const char* value)
{
    PODConfigurationElement*    cfgElement;


    /*
     * Find the named item.
     */
    for (cfgElement = this->mConfig; cfgElement->name != NULL; cfgElement++)
    {
        if (strcmp(name, cfgElement->name) == 0)
        {
            break;
        }
    }

    /*
     * Cant set that which does not exist!
     */
    if ( !cfgElement->name )
    {
        return;
    }

    /*
     * OK time to do some work...
     */

    talpa_mutex_lock(&this->mSemaphore);

    if (strcmp(name, CFG_STATUS) == 0)
    {
        if (strcmp(value, CFG_ACTION_ENABLE) == 0)
        {
            enable(this);
        }
        else if (strcmp(value, CFG_ACTION_DISABLE) == 0)
        {
            disable(this);
        }
    }
    else if ( !strcmp(name, CFG_OPS) )
    {
        doSpecialString(this, value);
    }

    talpa_mutex_unlock(&this->mSemaphore);

    return;
}

/*
 * End of lsm_interceptor.c
 */
