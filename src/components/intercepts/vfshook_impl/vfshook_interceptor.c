/*
 * vfshook_interceptor.c
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
#include <linux/version.h>
#define __NO_VERSION__
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/smp_lock.h>
#include <linux/unistd.h>

#include <linux/mount.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,3)
#include <linux/syscalls.h>
#endif
#include <linux/namei.h>
#include <linux/moduleparam.h>
#endif
#include <linux/smb_fs.h>


#include "vfshook_interceptor.h"
#include "app_ctrl/iportability_app_ctrl.h"
#include "filesystem/ifile_info.h"
#include "platforms/linux/alloc.h"
#include "platforms/linux/glue.h"


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
static void deleteVFSHookInterceptor(struct tag_VFSHookInterceptor* object);

static VFSHookObject* appendObject(void* self, talpa_list_head* list, const char* value, bool protected);
static VFSHookObject* findObject(const void* self, talpa_list_head* list, const char* value);
static void freeObject(VFSHookObject* obj);
static void deleteObject(void *self, VFSHookObject* obj);
static void constructSpecialSet(void* self);
static void doActionString(void* self, talpa_list_head* list, char** set, const char* value);
static void destroyStringSet(void *self, char **set);

static long talpaDummyOpen(unsigned int fd);
static void talpaDummyClose(unsigned int fd);
static long talpaDummyUselib(const char* library);
static int  talpaDummyExecve(const char* name);
static long talpaPreMount(char* dev_name, char* dir_name, char* type, unsigned long flags, void* data);
static void talpaPostMount(int err, char* dev_name, char* dir_name, char* type, unsigned long flags, void* data);
static void talpaPreUmount(char* name, int flags);
static void talpaPostUmount(int err, char* name, int flags);

static int processMount(struct vfsmount* mnt, unsigned long flags, bool fromMount);

/*
 * Constants
 */
#define CFG_STATUS          "status"
#define CFG_OPS             "ops"
#define CFG_FS              "fs-ignore"
#define CFG_NOSCAN          "no-scan"
#define CFG_PATCHLIST       "fs-list"
#define CFG_VALUE_ENABLED   "enabled"
#define CFG_VALUE_DISABLED  "disabled"
#define CFG_ACTION_ENABLE   "enable"
#define CFG_ACTION_DISABLE  "disable"
#define CFG_VALUE_DUMMY     "(empty)"

#define HOOK_OPEN       0x01
#define HOOK_CLOSE      0x02
#define HOOK_MOUNT      0x10
#define HOOK_UMOUNT     0x20

#define HOOK_DEFAULT (HOOK_OPEN | HOOK_CLOSE | HOOK_MOUNT | HOOK_UMOUNT)

/*
 * Singleton object.
 */

static VFSHookInterceptor GL_object =
    {
        {
            enable,
            disable,
            isEnabled,
            addInterceptProcessor,
            interceptProcessor,
            &GL_object,
            (void (*)(void*))deleteVFSHookInterceptor
        },
        {
            configName,
            allConfig,
            config,
            setConfig,
            &GL_object,
            (void (*)(void*))deleteVFSHookInterceptor
        },
        deleteVFSHookInterceptor,
        false,
        ATOMIC_INIT(0),
        { },
        TALPA_STATIC_MUTEX(GL_object.mSemaphore),
        0,
        HOOK_DEFAULT,
        TALPA_RCU_UNLOCKED,
        TALPA_LIST_HEAD_INIT(GL_object.mPatches),
        TALPA_RCU_UNLOCKED,
        TALPA_LIST_HEAD_INIT(GL_object.mSkipFilesystems),
        TALPA_LIST_HEAD_INIT(GL_object.mNoScanFilesystems),
        NULL,
        {
            {GL_object.mConfigData.name, GL_object.mConfigData.value, VFSHOOK_CFGDATASIZE, true, true },
            {GL_object.mOpsConfigData.name, GL_object.mOpsConfigData.value, VFSHOOK_OPSCFGDATASIZE, true, false },
            {GL_object.mSkipListConfigData.name, GL_object.mSkipListConfigData.value, VFSHOOK_FSCFGDATASIZE, true, false },
            {GL_object.mNoScanConfigData.name, GL_object.mNoScanConfigData.value, VFSHOOK_FSCFGDATASIZE, true, false },
            {GL_object.mPatchConfigData.name, GL_object.mPatchConfigData.value, VFSHOOK_FSCFGDATASIZE, false, false },
            {NULL, NULL, 0, false, false }
        },
        { CFG_STATUS, CFG_VALUE_DISABLED },
        { CFG_OPS, CFG_VALUE_DUMMY },
        { CFG_FS, CFG_VALUE_DUMMY },
        { CFG_NOSCAN, CFG_VALUE_DUMMY },
        { CFG_PATCHLIST, CFG_VALUE_DUMMY },
        NULL,
        NULL,
        {
            .open_post = talpaDummyOpen,
            .close_pre = talpaDummyClose,
            .execve_pre = talpaDummyExecve,
            .uselib_pre = talpaDummyUselib,
            .mount_pre = talpaPreMount,
            .mount_post = talpaPostMount,
            .umount_pre = talpaPreUmount,
            .umount_post = talpaPostUmount,
        },
        NULL,
        NULL,
        NULL,
    };

#define this    ((VFSHookInterceptor*)self)


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

static inline struct patchedFilesystem* getPatch(struct patchedFilesystem* patch)
{
    atomic_inc(&patch->refcnt);

    return patch;
}

static inline void putPatch(struct patchedFilesystem* patch)
{
    atomic_dec(&patch->refcnt);
}

static int talpaOpen(struct inode *inode, struct file *file)
{
    struct patchedFilesystem *p;
    struct patchedFilesystem *patch = NULL;
    int ret = -ESRCH;


    hookEntry();

    talpa_rcu_read_lock(&GL_object.mPatchLock);

    talpa_list_for_each_entry_rcu(p, &GL_object.mPatches, head)
    {
        if ( inode->i_fop == p->f_ops )
        {
            patch = getPatch(p);
            break;
        }
    }

    talpa_rcu_read_unlock(&GL_object.mPatchLock);

    if ( likely( patch != NULL ) )
    {
        ret = 0;
        /* Do not examine if we should not intercept opens and we are already examining one */
        if ( likely( ((GL_object.mInterceptMask & HOOK_OPEN) != 0) && !(current->flags & PF_TALPA_INTERNAL) ) )
        {
            /* First check with the examineInode method */
            ret = GL_object.mTargetProcessor->examineInode(GL_object.mTargetProcessor, EFS_Open, flags_to_writable(file->f_flags), file->f_flags, kdev_t_to_nr(inode_dev(inode)), inode->i_ino);

            if ( ret == -EAGAIN )
            {
                IFileInfo *pFInfo;


                pFInfo = GL_object.mLinuxFilesystemFactory->i_IFilesystemFactory.newFileInfoFromFile(GL_object.mLinuxFilesystemFactory, EFS_Open, file);
                if ( likely( pFInfo != NULL ) )
                {
                    /* Make sure our open and close attempts while examining will be excluded */
                    current->flags |= PF_TALPA_INTERNAL;
                    /* Examine this file */
                    ret = GL_object.mTargetProcessor->examineFileInfo(GL_object.mTargetProcessor, pFInfo, NULL);
                    /* Restore normal process examination */
                    current->flags &= ~PF_TALPA_INTERNAL;
                    pFInfo->delete(pFInfo);
                }
            }

            if ( likely( (ret == 0) && patch->open ) )
            {
                ret = patch->open(inode, file);
            }
        }
        else if ( patch->open )
        {
            ret = patch->open(inode, file);
        }

        putPatch(patch);
    }
    else
    {
        err("Open left patched after record removed!");
    }

    hookExitRv(ret);
}

static int talpaRelease(struct inode *inode, struct file *file)
{
    struct patchedFilesystem *p;
    struct patchedFilesystem *patch = NULL;
    int ret = -ESRCH;


    hookEntry();

    talpa_rcu_read_lock(&GL_object.mPatchLock);

    talpa_list_for_each_entry_rcu(p, &GL_object.mPatches, head)
    {
        if ( inode->i_fop == p->f_ops )
        {
            patch = getPatch(p);
            break;
        }
    }

    talpa_rcu_read_unlock(&GL_object.mPatchLock);

    if ( likely( patch != NULL ) )
    {
        ret = 0;
        /* Do not examine if we should not intercept closes and we are already examining one */
        if ( likely( ((GL_object.mInterceptMask & HOOK_CLOSE) != 0) && !(current->flags & PF_TALPA_INTERNAL) ) )
        {
            IFileInfo *pFInfo;

            pFInfo = GL_object.mLinuxFilesystemFactory->i_IFilesystemFactory.newFileInfoFromFile(GL_object.mLinuxFilesystemFactory, EFS_Close, file);
            /* Make sure our open and close attempts while examining will be excluded */
            current->flags |= PF_TALPA_INTERNAL;
            if ( likely( pFInfo != NULL ) )
            {
                GL_object.mTargetProcessor->examineFileInfo(GL_object.mTargetProcessor, pFInfo, NULL);
                pFInfo->delete(pFInfo);
            }
            if ( patch->release )
            {
                ret = patch->release(inode, file);
            }
            /* Restore normal process examination */
            current->flags &= ~PF_TALPA_INTERNAL;
        }
        else if ( patch->release )
        {
            ret = patch->release(inode, file);
        }

        putPatch(patch);
    }
    else
    {
        err("Close left patched after record removed!");
    }

    hookExitRv(ret);
}

static int talpaIoctl(struct inode *inode, struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct patchedFilesystem *p;
    struct patchedFilesystem *patch = NULL;
    int err = -ESRCH;


    hookEntry();

    talpa_rcu_read_lock(&GL_object.mPatchLock);

    talpa_list_for_each_entry_rcu(p, &GL_object.mPatches, head)
    {
        if ( inode->i_fop == p->sf_ops )
        {
            patch = getPatch(p);
            dbg("ioctl on %s", patch->fstype->name);
            break;
        }
    }

    talpa_rcu_read_unlock(&GL_object.mPatchLock);

    if ( patch )
    {
        if ( patch->ioctl )
        {
            err = patch->ioctl(inode, filp, cmd, arg);

            if ( cmd == SMB_IOC_NEWCONN )
            {
                if ( !err )
                {
                    processMount(filp->f_vfsmnt, filp->f_vfsmnt->mnt_flags, false);
                }
                else
                {
                    dbg("smbfs newconn ioctl failed (%d)!", err);
                }
            }
            else
            {
                dbg("Unexpected smbmount behaviour!");
            }
        }
        else
        {
            err = -ENOTTY;
            err("smbfs_ioctl unexpectedly missing!");
        }

        putPatch(patch);
    }

    hookExitRv(err);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
static int talpaInodeCreate(struct inode *inode, struct dentry *dentry, int mode, struct nameidata *nd)
#else
static int talpaInodeCreate(struct inode *inode, struct dentry *dentry, int mode)
#endif
{
    struct patchedFilesystem *p;
    struct patchedFilesystem *patch = NULL;
    int err = -ESRCH;


    hookEntry();

    talpa_rcu_read_lock(&GL_object.mPatchLock);

    talpa_list_for_each_entry_rcu(p, &GL_object.mPatches, head)
    {
        if ( inode->i_op == p->i_ops )
        {
            patch = getPatch(p);
            dbg("Create on %s", patch->fstype->name);
            break;
        }
    }

    talpa_rcu_read_unlock(&GL_object.mPatchLock);

    if ( patch )
    {
        /* First call the original hook so that the inode gets created */
        if ( patch->create )
        {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
            err = patch->create(inode, dentry, mode, nd);
#else
            err = patch->create(inode, dentry, mode);
#endif
        }

        /* If creation was successfull try to resolve the created inode
           and also pass it through for interception. */
        if ( !err )
        {
            /* Check if this is a regular file */
            if ( dentry && dentry->d_inode && S_ISREG(dentry->d_inode->i_mode) )
            {
                IFileInfo *pFInfo;


                /* Re-patch, this time using file operations */
                dbg("  restoring inode operations [0x%p][0x%p 0x%p]", patch->i_ops, patch->lookup, patch->create);
                patch->i_ops->lookup = patch->lookup;
                patch->i_ops->create = patch->create;
                patch->lookup = NULL;
                patch->create = NULL;
                if ( patch->sf_ops && patch->sf_ops->ioctl == talpaIoctl )
                {
                    dbg("  restoring smbfs ioctl operation [0x%p][0x%p]", patch->sf_ops, patch->ioctl);
                    patch->sf_ops->ioctl = patch->ioctl;
                    patch->sf_ops = NULL;
                    patch->ioctl = NULL;
                }
                patch->i_ops = (struct inode_operations *)dentry->d_inode->i_op;
                dbg("  storing original inode operations [0x%p]", patch->i_ops);
                patch->f_ops = (struct file_operations *)dentry->d_inode->i_fop;
                patch->open = patch->f_ops->open;
                patch->release = patch->f_ops->release;
                dbg("  storing original file operations [0x%p][0x%p 0x%p]", patch->f_ops, patch->open, patch->release);
                patch->f_ops->open = talpaOpen;
                patch->f_ops->release = talpaRelease;
                smp_wmb();

                dbg("Patching file operations 0x%p 0x%p", patch->open, patch->release);

                /* Do not examine if we should not intercept opens or we are already examining one */
                if ( likely( ((GL_object.mInterceptMask & HOOK_OPEN) != 0) && !(current->flags & PF_TALPA_INTERNAL) ) )
                {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
                    pFInfo = GL_object.mLinuxFilesystemFactory->i_IFilesystemFactory.newFileInfoFromDirectoryEntry(GL_object.mLinuxFilesystemFactory, EFS_Open, dentry, nd->mnt, O_CREAT | O_EXCL, mode);

                    if ( pFInfo )
                    {
                        /* Make sure our open and close attempts while examining will be excluded */
                        current->flags |= PF_TALPA_INTERNAL;
                        err = GL_object.mTargetProcessor->examineFileInfo(GL_object.mTargetProcessor, pFInfo, NULL);
                        /* Restore normal process examination */
                        current->flags &= ~PF_TALPA_INTERNAL;
                        pFInfo->delete(pFInfo);
                    }
#else
                    pFInfo = GL_object.mLinuxFilesystemFactory->i_IFilesystemFactory.newFileInfoFromInode(GL_object.mLinuxFilesystemFactory, EFS_Open, inode, O_CREAT | O_EXCL);

                    if ( pFInfo )
                    {
                        /* Make sure our open and close attempts while examining will be excluded */
                        current->flags |= PF_TALPA_INTERNAL;
                        err = GL_object.mTargetProcessor->runAllowChain(GL_object.mTargetProcessor, pFInfo);
                        /* Restore normal process examination */
                        current->flags &= ~PF_TALPA_INTERNAL;
                        pFInfo->delete(pFInfo);
                    }
#endif
                }
            }
        }

        putPatch(patch);
    }

    hookExitRv(err);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
static struct dentry* talpaInodeLookup(struct inode *inode, struct dentry *dentry, struct nameidata *nd)
#else
static struct dentry* talpaInodeLookup(struct inode *inode, struct dentry *dentry)
#endif
{
    struct patchedFilesystem *p;
    struct patchedFilesystem *patch = NULL;
    struct dentry* err = ERR_PTR(-ESRCH);


    hookEntry();

    talpa_rcu_read_lock(&GL_object.mPatchLock);

    talpa_list_for_each_entry_rcu(p, &GL_object.mPatches, head)
    {
        if ( inode->i_op == p->i_ops )
        {
            patch = getPatch(p);
            dbg("Lookup on %s", patch->fstype->name);
            break;
        }
    }

    talpa_rcu_read_unlock(&GL_object.mPatchLock);

    if ( patch )
    {
        /* First call the original hook so that the inode gets looked up */
        if ( patch->lookup )
        {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
            err = patch->lookup(inode, dentry, nd);
#else
            err = patch->lookup(inode, dentry);
#endif
        }

        /* If the lookup was successfull try to repatch
           if the target is a regular file. */
        if ( !err && !IS_ERR(dentry) )
        {
            /* Check if this is a regular file */
            if ( dentry && dentry->d_inode && S_ISREG(dentry->d_inode->i_mode) )
            {
                /* Re-patch, this time using file operations */
                dbg("  restoring inode operations [0x%p][0x%p 0x%p]", patch->i_ops, patch->lookup, patch->create);
                patch->i_ops->lookup = patch->lookup;
                patch->i_ops->create = patch->create;
                patch->lookup = NULL;
                patch->create = NULL;
                if ( patch->sf_ops && patch->sf_ops->ioctl == talpaIoctl )
                {
                    dbg("  restoring smbfs ioctl operation [0x%p][0x%p]", patch->sf_ops, patch->ioctl);
                    patch->sf_ops->ioctl = patch->ioctl;
                    patch->sf_ops = NULL;
                    patch->ioctl = NULL;
                }
                patch->i_ops = (struct inode_operations *)dentry->d_inode->i_op;
                dbg("  storing original inode operations [0x%p]", patch->i_ops);
                patch->f_ops = (struct file_operations *)dentry->d_inode->i_fop;
                patch->open = patch->f_ops->open;
                patch->release = patch->f_ops->release;
                dbg("  storing original file operations [0x%p][0x%p 0x%p]", patch->f_ops, patch->open, patch->release);
                patch->f_ops->open = talpaOpen;
                patch->f_ops->release = talpaRelease;
                smp_wmb();

                dbg("Patching file operations 0x%p 0x%p", patch->open, patch->release);
            }
        }

        putPatch(patch);
    }

    hookExitRv(err);
}

/* Structure which holds info on one entry as we scan the directory tree */
struct dentryContext
{
    struct file*    dir;
    char*           dirent;
    size_t          bufsize;
    bool            overflow;
    bool            fill;
    bool            skip;
    char*           root;
    size_t          rootsize;
    unsigned int    rootlen;
};

/* Callback we supply to vfs_readdir in order to get dentry info */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19) || defined TALPA_HAS_BACKPORTED_FILLDIR
static int fillDentry(void * __buf, const char * name, int namlen, loff_t offset, u64 ino, unsigned int d_type)
#elif LINUX_VERSION_CODE > KERNEL_VERSION(2,4,8)
static int fillDentry(void * __buf, const char * name, int namlen, loff_t offset, ino_t ino, unsigned int d_type)
#else
static int fillDentry(void * __buf, const char * name, int namlen, off_t offset, ino_t ino, unsigned int d_type)
#endif
{
    struct dentryContext *dc = (struct dentryContext *)__buf;


    /* Skip current and parent directory inodes.
       Also skip zero-length names which smbfs can provide in some cases. */
    if ( (namlen == 0) || (name == NULL) || (*name == 0) ||
        ((namlen == 1) && !strncmp(name, ".", 1)) ||
        ((namlen == 2) && !strncmp(name, "..", 2)) )
    {
        return 0;
    }
    /* Skip this dentry if requested so */
    else if ( dc->skip )
    {
        dc->skip = false;
        return 0;
    }

    /* Check if we have enough space in dirent to copy the whole path in */
    if ( dc->bufsize < (strlen(dc->root) + 1 + namlen + 1) )
    {
        dc->overflow = true;
        dbg("pathname too long, skipping");
        return 0;
    }

    /* We have a potentially interesting dentry */
    dc->fill = true;

    strcpy(dc->dirent, dc->root);
    if ( dc->root[dc->rootlen - 1] != '/' )
    {
        strcat(dc->dirent, "/");
    }
    strncat(dc->dirent, name, namlen);

    return -EBFONT;
}

static void stripLastPathElement(char* path)
{
    char* p;


    /* Position ourselves at the last character */
    p = path + strlen(path) - 1;

    /* Skip trailing slash */
    if ( (*p != '/') && (p > path) )
        *p-- = 0;

    /* Find previous slash */
    while ( (*p != '/') && (p > path) )
        p--;

    /* Null terminate at the slash, or at one after if this is a root directory */
    if ( p > path )
    {
        *p = 0;
    }
    else
    {
        *++p = 0;
    }
}

struct openDirectory
{
    talpa_list_head head;
    unsigned int    level;
    char*           name;
    struct file*    dir;
};

struct directories
{
    talpa_list_head list;
    unsigned int    dmax;
    unsigned int    cmax;
    unsigned int    count;
};

static void initDirectories(struct directories* dirs)
{
    TALPA_INIT_LIST_HEAD(&dirs->list);
    dirs->dmax = 0;
    dirs->cmax = 0;
    dirs->count = 0;
}

static char* namedup(char *name)
{
    char *tmp;
    size_t len = strlen(name) + 1;


    tmp = talpa_alloc(len);
    if ( tmp )
    {
        memcpy(tmp, name, len);
    }

    return tmp;
}

static void purgeDirectories(struct directories* dirs, unsigned int depth)
{
    struct openDirectory* tmp;
    struct openDirectory* dir = NULL;


    talpa_list_for_each_entry_safe(dir, tmp, &dirs->list, head)
    {
        if ( dir->level == depth )
        {
            --dirs->count;
            talpa_list_del(&dir->head);
            dbg("deleting handle for %s at %u", dir->name, dir->level);
            filp_close(dir->dir, current->files);
            talpa_free(dir->name);
            talpa_free(dir);
        }
    }
}

static void cleanupDirectories(struct directories* dirs)
{
    struct openDirectory* tmp;
    struct openDirectory* dir = NULL;


    dbg("max depth was %u and max count %u", dirs->dmax, dirs->cmax);

    talpa_list_for_each_entry_safe(dir, tmp, &dirs->list, head)
    {
        talpa_list_del(&dir->head);
        dbg("deleting handle for %s at %u", dir->name, dir->level);
        filp_close(dir->dir, current->files);
        talpa_free(dir->name);
        talpa_free(dir);
    }
}

static struct file* openDirectory(struct directories* dirs, unsigned int depth, char* name, bool* newdir)
{
    struct openDirectory* tmp;
    struct openDirectory* dir = NULL;
    int ret = -ENOMEM;


    talpa_list_for_each_entry(tmp, &dirs->list, head)
    {
        if ( (tmp->level == depth) && !strcmp(tmp->name, name) )
        {
            dir = tmp;
            break;
        }

    }

    if ( dir )
    {
        dbg("found open handle for %s at %u", dir->name, dir->level);
        *newdir = false;
        return dir->dir;
    }
    else
    {
        dir = talpa_alloc(sizeof(struct openDirectory));

        if ( dir )
        {
            dir->level = depth;
            dir->name = namedup(name);
            if ( dir->name )
            {
                dir->dir = filp_open(dir->name, O_RDONLY | O_DIRECTORY, 0);
                if ( !IS_ERR(dir->dir) )
                {
                    if ( dir->level > dirs->dmax )
                    {
                        dirs->dmax = dir->level;
                    }
                    dirs->count++;
                    if ( dirs->count > dirs->cmax )
                    {
                        dirs->cmax = dirs->count;
                    }
                    *newdir = true;
                    purgeDirectories(dirs, depth);
                    talpa_list_add(&dir->head, &dirs->list);
                    dbg("added handle for %s at %u", dir->name, dir->level);

                    return dir->dir;
                }
                else
                {
                    ret = PTR_ERR(dir->dir);
                    dbg("open directory for %s failed (%d)", dir->name, ret);
                }
                talpa_free(dir->name);
            }
            talpa_free(dir);
        }
    }

    return ERR_PTR(ret);
}

static struct dentry *scanDirectory(const char* dirname, char* rootbuf, size_t rootsize, char* buf, size_t bufsize, bool* overflow)
{
    struct dentry *reg = NULL;
    struct dentryContext* dc;
    struct nameidata* nd;
    int err;
    bool newdir = false;
    struct directories dirs;
    unsigned int depth = 0;


    initDirectories(&dirs);
    /* Allocate structures and memory */
    dc = talpa_alloc(sizeof(struct dentryContext));
    nd = talpa_alloc(sizeof(struct nameidata));

    if ( !dc || !nd )
    {
        goto out;
    }

    dc->rootsize = rootsize;
    dc->root = rootbuf;
    dc->bufsize = bufsize;
    dc->dirent = buf;
    strcpy(dc->root, dirname);
    dc->rootlen = strlen(dc->root);

    dbg("root at %s, max path %lu bytes", dc->root, dc->bufsize);
rescan:
    dc->dir = openDirectory(&dirs, depth, dc->root, &newdir);

    /* Back-out if we failed to open, abort if we are at given root */
    if ( IS_ERR(dc->dir) )
    {
        if ( !strcmp(dirname, dc->root) )
        {
            dbg("backed out to root (err %ld)", PTR_ERR(dc->dir));
            goto out;
        }

        stripLastPathElement(dc->root);
        purgeDirectories(&dirs, depth);
        --depth;
        dbg("backing out to %s (%ld) [%u]", dc->root, PTR_ERR(dc->dir), depth);
        dc->rootlen = strlen(dc->root);
        goto rescan;
    }

    dc->skip = false;

    do
    {
        /* Fill flag will be set in fillDentry if an
           interesting dentry is found. */
        dc->fill = false;
        /* Overflow signals that the dirent buffer was
           to small for at least one path in this scan. */
        dc->overflow = false;
        /* Skip first entry if we are continuing to
           read an open directory.  */
        if ( !newdir )
        {
            dc->skip = true;
        }
        err = vfs_readdir(dc->dir, fillDentry, dc);
        newdir = false;
        *overflow |= dc->overflow;

        /* Back-out if at end-of-directory or if error occured */
        if ( ((err < 0) && (err != -EBFONT)) || !dc->fill )
        {
            if ( !strcmp(dirname, dc->root) )
            {
                dbg("eod");
                goto out;
            }

            stripLastPathElement(dc->root);
            purgeDirectories(&dirs, depth);
            --depth;
            dbg("backing out to %s (%d)", dc->root, err);
            dc->rootlen = strlen(dc->root);
            goto rescan;
        }

        /* Try to lookup it... */
        err = talpa_path_lookup(dc->dirent, 0, nd);

        if ( err == 0 )
        {
            /* If dentry resolves to regular file we're done! */
            if ( S_ISREG(nd->dentry->d_inode->i_mode) )
            {
                dbg("regular %s", dc->dirent);
                reg = dget(nd->dentry);
            }
            /* If it is a directory and not a root of a mounted filesystem, enter into it.
               But only if we have enough space in the buffer to copy that path. */
            else if ( S_ISDIR(nd->dentry->d_inode->i_mode) && (nd->dentry != nd->mnt->mnt_root) && (dc->rootsize > strlen(dc->dirent)) )
            {
                dbg("entering %s", dc->dirent);
                depth++;
                path_release(nd);
                strcpy(dc->root, dc->dirent);
                dc->rootlen = strlen(dc->root);
                goto rescan;
            }
            else
            {
                dbg("  skipping %s", dc->dirent);
            }
            path_release(nd);
        }
    } while ( !reg ); /* !reg = search finished, we have a regular file */

out:
    talpa_free(nd);
    talpa_free(dc);
    cleanupDirectories(&dirs);

    return reg;
}

/* Find a regular file on a given vfsmount. dgets it's dentry. */
static struct dentry *findRegular(struct vfsmount* root)
{
    struct dentry *reg = NULL;
    struct dentry *droot;
    struct vfsmount *mntroot;
    char *path, *name;
    size_t path_size = 0;
    bool overflow;
    char *rootbuf, *buf;
    size_t root_size = 0;
#if defined __GFP_NOWARN && defined __GFP_NORETRY
    unsigned int max_order = 3;
#else
    unsigned int max_order = 0;
#endif
    unsigned int mnt_order, dir_order;


    /* Allocate storage and build mount point path */
    droot = dget(root->mnt_root);
    mntroot = mntget(root);
    for (mnt_order = 0; mnt_order <= max_order; mnt_order++)
    {
        path = talpa_alloc_path_order(mnt_order, &path_size);
        /* Fail immediately if allocation failed since chances are low
           the higher order one will succeed. */
        if ( !path )
        {
            dbg("failed to allocate order %u", mnt_order);
            goto exit1;
        }
        name = d_path(root->mnt_root, root, path, path_size);
        if ( IS_ERR(name) )
        {
            talpa_free_path_order(path, mnt_order);
            if ( PTR_ERR(name) == -EOVERFLOW )
            {
                /* Try with a larger buffer if there was not enough room for a path */
                dbg("order %u is insufficient", mnt_order);
            }
            else
            {
                /* Unexpected failure */
                dbg("unexpected failure %d", PTR_ERR(name));
                goto exit1;
            }
        }
        else
        {
            /* Success */
            dbg("mount point path %s (%u)", name, mnt_order);
            break;
        }
    }

    /* Failed to build mount point path? */
    if ( IS_ERR(name) )
    {
        dbg("max order of %u was insufficient (%u)", max_order, PTR_ERR(name));
        goto exit1;
    }

    /* Now scan the mount point path */
    for (dir_order = 0; dir_order <= max_order; dir_order++)
    {
        rootbuf = talpa_alloc_path_order(dir_order, &root_size);
        buf = talpa_alloc_path_order(dir_order, &path_size);
        if ( !rootbuf || !buf )
        {
            dbg("failed to allocate order %u", dir_order);
            break;
        }
        overflow = false;
        reg = scanDirectory(name, rootbuf, root_size, buf, path_size, &overflow);
        if ( !reg && overflow )
        {
            /* Try with a larger buffer */
            dbg("order %u is insufficient", dir_order);
            talpa_free_path_order(rootbuf, dir_order);
            talpa_free_path_order(buf, dir_order);
            continue;
        }
        dbg("found regular dentry 0x%p", reg);
        break;
    }

    talpa_free_path_order(rootbuf, dir_order);
    talpa_free_path_order(buf, dir_order);
    talpa_free_path_order(path, mnt_order);
exit1:
    mntput(mntroot);
    dput(droot);

    return reg;
}

static int prepareFilesystem(struct vfsmount* mnt, struct dentry* dentry, bool smbfs, struct patchedFilesystem* patch)
{
    if ( !mnt )
    {
        err("No vfsmount object!");
        return -EINVAL;
    }

    if ( !patch )
    {
        err("Not enough memory to patch %s", mnt->mnt_sb->s_type->name);
        return -ENOMEM;
    }

    if ( patch->f_ops || patch->i_ops )
    {
        dbg("Filesystem %s already patched", mnt->mnt_sb->s_type->name);
        return 0;
    }

    /* If we have a regular file prepare for file_operations patching */
    if ( dentry && S_ISREG(dentry->d_inode->i_mode) )
    {
        patch->i_ops = (struct inode_operations *)dentry->d_inode->i_op;
        dbg("  storing original inode operations [0x%p]", patch->i_ops);
        patch->f_ops = (struct file_operations *)dentry->d_inode->i_fop;
        patch->open = patch->f_ops->open;
        patch->release = patch->f_ops->release;
        dbg("  storing original file operations [0x%p][0x%p 0x%p]", patch->f_ops, patch->open, patch->release);
    }
    /* If called directly from smbfs mount prepare for ioctl patching (we never have regular file here) */
    else if ( dentry && smbfs )
    {
        patch->sf_ops = (struct file_operations *)dentry->d_inode->i_fop;
        patch->ioctl = patch->sf_ops->ioctl;
        dbg("  storing original smbfs file operations [0x%p][0x%p]", patch->sf_ops, patch->ioctl);
    }
    /* Otherwise prepare for inode_operations patching */
    else
    {
        if ( !dentry )
        {
            dentry = mnt->mnt_root;
            dbg("  root dentry [0x%p]", dentry);
        }

        patch->i_ops = (struct inode_operations *)dentry->d_inode->i_op;
        patch->lookup = patch->i_ops->lookup;
        patch->create = patch->i_ops->create;
        dbg("  storing original inode operations [0x%p][0x%p 0x%p]", patch->i_ops, patch->lookup, patch->create);

    }

    return 0;
}

static int patchFilesystem(struct vfsmount* mnt, struct dentry* dentry, bool smbfs, struct patchedFilesystem* patch)
{
    /* If we have a regular file from this filesystem we patch the file_operations */
    if ( dentry && S_ISREG(dentry->d_inode->i_mode) )
    {
        dbg("  patching file operations [0x%p][0x%p 0x%p]", patch->f_ops, patch->open, patch->release);
        patch->f_ops->open = talpaOpen;
        patch->f_ops->release = talpaRelease;
    }
    else if ( dentry && smbfs )
    {
        dbg("  patching smbfs ioctl [0x%p][0x%p]", patch->sf_ops, patch->ioctl);
        patch->sf_ops->ioctl = talpaIoctl;
    }
    else
    {
        patch->i_ops->lookup = talpaInodeLookup;
        patch->i_ops->create = talpaInodeCreate;
        dbg("  patching inode operations [0x%p][0x%p 0x%p]", patch->i_ops, patch->lookup, patch->create);
    }
    smp_wmb();

    dbg("Patched filesystem %s", mnt->mnt_sb->s_type->name);

    return 0;
}

static bool repatchFilesystem(struct vfsmount* mnt, struct dentry* dentry, bool smbfs, struct patchedFilesystem* patch)
{
    bool shouldinc = true;

    /* No-op if already patched */
    if ( patch->f_ops && (patch->f_ops->open == talpaOpen) )
    {
        dbg("Filesystem %s already patched, no repatching necessary", mnt->mnt_sb->s_type->name);
        return true;
    }

    /* If we have a regular file from this filesystem we patch the file_operations */
    if ( dentry && S_ISREG(dentry->d_inode->i_mode) )
    {
        if ( patch->i_ops->lookup == talpaInodeLookup )
        {
            dbg("  restoring inode lookup operation [0x%p][0x%p]", patch->i_ops, patch->lookup);
            patch->i_ops->lookup = patch->lookup;
            patch->lookup = NULL;
        }

        if ( patch->i_ops->create == talpaInodeCreate )
        {
            dbg("  restoring inode create operation [0x%p][0x%p]", patch->i_ops, patch->create);
            patch->i_ops->create = patch->create;
            patch->create = NULL;
        }

        if ( patch->sf_ops && (patch->sf_ops->ioctl == talpaIoctl) )
        {
            /* Never happens on mount, we can have regular file only when smbfs ioctl calls processMount */
            dbg("  restoring smbfs ioctl operation [0x%p][0x%p]", patch->sf_ops, patch->ioctl);
            patch->sf_ops->ioctl = patch->ioctl;
            patch->sf_ops = NULL;
            patch->ioctl = NULL;
            shouldinc = false;
        }

        patch->f_ops = (struct file_operations *)dentry->d_inode->i_fop;
        patch->open = patch->f_ops->open;
        patch->release = patch->f_ops->release;
        dbg("  storing original file operations [0x%p][0x%p 0x%p]", patch->f_ops, patch->open, patch->release);
        dbg("  patching file operations [0x%p][0x%p 0x%p]", patch->f_ops, patch->open, patch->release);
        patch->f_ops->open = talpaOpen;
        patch->f_ops->release = talpaRelease;
        smp_wmb();
    }
    else if ( smbfs )
    {
        /* Called directly from mount, fops are not patched, iops are so nothing to do here.
            But we want to increase usecnt so will not signal otherwise. */
        dbg("Do nothing for smbfs mounts before ioctl gets called.");
    }
    else
    {
        /* We will only get here if re-patching a fs which doesn't already
           have fops->open patched and we didn't find a regular file. Normally
           we ignore it since it means inode operations are already patched.
           But in some cases (smbfs) we might arrive here with i_ops unpatched. */

        if ( patch->i_ops )
        {
            if ( patch->sf_ops )
            {
                /* Don't increase usecnt since this is a post smbfs ioctl path. */
                shouldinc = false;
                dbg("Not increasing usecnt for post ioctl smbfs mounts.");
            }
            if ( patch->i_ops->lookup != talpaInodeLookup )
            {
                dbg("  patching inode lookup [0x%p][0x%p]", patch->i_ops, patch->lookup);
                patch->i_ops->lookup = talpaInodeLookup;
            }
            if ( patch->i_ops->create != talpaInodeCreate )
            {
                dbg("  patching inode creation [0x%p][0x%p]", patch->i_ops, patch->create);
                patch->i_ops->create = talpaInodeCreate;
            }
            smp_wmb();
        }
    }

    dbg("Re-patched filesystem %s", mnt->mnt_sb->s_type->name);

    return shouldinc;
}

static int restoreFilesystem(struct patchedFilesystem* patch)
{
    if ( patch->sf_ops )
    {
        dbg("Restoring smbfs file operations 0x%p 0x%p", patch->sf_ops, patch->ioctl);
        patch->sf_ops->ioctl = patch->ioctl;
        smp_wmb();
    }

    if ( patch->f_ops )
    {
        dbg("Restoring file operations 0x%p 0x%p", patch->open, patch->release);
        patch->f_ops->open = patch->open;
        patch->f_ops->release = patch->release;
        patch->f_ops->ioctl = patch->ioctl;
        smp_wmb();
    }
    else if ( patch->i_ops )
    {
        if ( patch->i_ops->lookup == talpaInodeLookup )
        {
            dbg("Restoring lookup inode operation 0x%p", patch->lookup);
            patch->i_ops->lookup = patch->lookup;
            patch->lookup = NULL;
        }
        if ( patch->i_ops->create == talpaInodeCreate )
        {
            dbg("Restoring create inode operation 0x%p", patch->create);
            patch->i_ops->create = patch->create;
            patch->create = NULL;
        }
        smp_wmb();
    }
    else
    {
        err("Restore on an unpatched filesystem!");
    }

    return 0;
}

static bool onNoScanList(const char *name)
{
    VFSHookObject* obj;
    bool found = false;


    talpa_rcu_read_lock(&GL_object.mListLock);
    talpa_list_for_each_entry(obj, &GL_object.mNoScanFilesystems, head)
    {
        if ( !strcmp(name, obj->value) )
        {
            dbg("%s is on no scan list", name);
            found = true;
            break;
        }
    }
    talpa_rcu_read_unlock(&GL_object.mListLock);

    return found;
}

static int processMount(struct vfsmount* mnt, unsigned long flags, bool fromMount)
{
    struct patchedFilesystem*   p;
    struct patchedFilesystem*   patch = NULL;
    struct patchedFilesystem*   newpatch;
    struct dentry*              reg;
    VFSHookObject*              obj;
    int                         ret = -ESRCH;
    bool                        shouldinc;
    bool                        smbfs = false;
    const char*                 fsname = (const char *)mnt->mnt_sb->s_type->name;


    /* We don't want to patch some filesystems */
    talpa_rcu_read_lock(&GL_object.mListLock);
    talpa_list_for_each_entry_rcu(obj, &GL_object.mSkipFilesystems, head)
    {
        if ( !strcmp(fsname, obj->value) )
        {
            dbg("%s is on the skip list", obj->value);
            talpa_rcu_read_unlock(&GL_object.mListLock);
            return 0;
        }
    }
    talpa_rcu_read_unlock(&GL_object.mListLock);

    /* Allocate patchedFilesystem structure because we
       can't do it while holding a lock. */
    newpatch = talpa_alloc(sizeof(struct patchedFilesystem));

    /* We do not want to search for files on some filesystems on mount. */
    if ( fromMount && onNoScanList(fsname) )
    {
        reg = dget(mnt->mnt_root);
        /* Special patching workaround for smbfs is required */
        if ( !strcmp(fsname, "smbfs") )
        {
            smbfs = true;
        }
    }
    else
    {
        /* Try to find one regular file, also before taking the lock. */
        reg = findRegular(mnt);
    }

    /* Check if we have already patched this filesystem */
    talpa_rcu_write_lock(&GL_object.mPatchLock);

    talpa_list_for_each_entry_rcu(p, &GL_object.mPatches, head)
    {
        if ( mnt->mnt_sb->s_type == p->fstype )
        {
            patch = p;
            break;
        }
    }

    /* If we found the patch, free the newly allocated one */
    if ( patch )
    {
        talpa_free(newpatch);
    }
    /* Othrewise set the patch to be the newpatch */
    else if ( newpatch )
    {
        patch = newpatch;
        memset(patch, 0, sizeof(struct patchedFilesystem));
        atomic_set(&patch->usecnt, 0);
        atomic_set(&patch->refcnt, 1);
        patch->fstype = mnt->mnt_sb->s_type;
    }

    /* prepareFilesystem knows how to handle different situations */
    ret = prepareFilesystem(mnt, reg, smbfs, patch);
    if ( !ret )
    {
        /* Only add it to the list if this is a new patch (not a new
           instance of the existing one) */
        if ( patch == newpatch )
        {
            dbg("refcnt for %s = %d", fsname, atomic_read(&patch->refcnt));
            talpa_list_add_rcu(&patch->head, &GL_object.mPatches);
            atomic_inc(&patch->usecnt);
            dbg("usecnt for %s = %d", fsname, atomic_read(&patch->usecnt));
            /* Actually patch the filesystem */
            patchFilesystem(mnt, reg, smbfs, patch);
        }
        else
        {
            /* Re-patch filesystem, increase usecnt if repatch thinks we should
               but never for re-mounts. */
            shouldinc = repatchFilesystem(mnt, reg, smbfs, patch);
            if ( shouldinc && !(flags & MS_REMOUNT) )
            {
                atomic_inc(&patch->usecnt);
                dbg("usecnt for %s = %d", fsname, atomic_read(&patch->usecnt));
            }
            else
            {
                dbg("usecnt for %s stayed %d", fsname, atomic_read(&patch->usecnt));
            }
        }
        /* Free list showed to userspace so it will be regenerated on next read */
        destroyStringSet(&GL_object, &GL_object.mPatchListSet);
    }
    else
    {
        /* Free newly allocated patch if patching failed */
        if ( patch == newpatch )
        {
            talpa_free(newpatch);
        }
    }

    talpa_rcu_write_unlock(&GL_object.mPatchLock);

    /* We don't need a reference to regular dentry any more so
       drop it if we had one. */
    if ( reg )
    {
        dput(reg);
    }

    return ret;
}

static long talpaDummyOpen(unsigned int fd)
{
    /* We do not want to intercept this through talpa-syscallhook! */
    err("Incorrect usage of talpa-syscallhook and talpa-vfshook modules!");

    return 0;
}

static void talpaDummyClose(unsigned int fd)
{
    /* We do not want to intercept this through talpa-syscallhook! */
    err("Incorrect usage of talpa-syscallhook and talpa-vfshook modules!");

    return;
}

static long talpaDummyUselib(const char* library)
{
    /* We do not want to intercept this through talpa-syscallhook! */
    err("Incorrect usage of talpa-syscallhook and talpa-vfshook modules!");

    return 0;
}

static int  talpaDummyExecve(const char* name)
{
    /* We do not want to intercept this through talpa-syscallhook! */
    err("Incorrect usage of talpa-syscallhook and talpa-vfshook modules!");

    return 0;
}

static long talpaPreMount(char* dev_name, char* dir_name, char* type, unsigned long flags, void* data)
{
    char* dev;
    char* dir;
    char* fstype;
    int decision = 0;
    IFilesystemInfo *pFSInfo;


    if ( unlikely( (GL_object.mInterceptMask & HOOK_MOUNT) == 0 ) )
    {
        return 0;
    }

    dev = getname(dev_name);

    if ( IS_ERR(dev) )
    {
        goto out;
    }

    dir = getname(dir_name);

    if ( IS_ERR(dir) )
    {
        goto out1;
    }

    fstype = getname(type);

    if ( IS_ERR(fstype) )
    {
        goto out2;
    }

    pFSInfo = GL_object.mLinuxFilesystemFactory->i_IFilesystemFactory.newFilesystemInfo(GL_object.mLinuxFilesystemFactory, EFS_Mount, dev, dir, fstype);

    if ( likely(pFSInfo != NULL) )
    {
        decision = GL_object.mTargetProcessor->examineFilesystemInfo(GL_object.mTargetProcessor, pFSInfo);
        pFSInfo->delete(pFSInfo);
        if ( unlikely( decision < 0 ) )
        {
            dbg("[intercepted %u-%u-%u] Mount blocked! decision:%d", processParentPID(current), current->tgid, current->pid, decision);
        }
    }
    else
    {
        dbg("[intercepted %u-%u-%u] Failed to examine mount!", processParentPID(current), current->tgid, current->pid);
    }

    putname(fstype);
out2:
    putname(dir);
out1:
    putname(dev);
out:
    return decision;
}

static void talpaPostMount(int err, char* dev_name, char* dir_name, char* type, unsigned long flags, void* data)
{
    struct nameidata nd;
    struct nameidata nd2;
    char* dir;
    char* path;
    size_t path_size;
    char* dir2;


#ifdef MS_MOVE
#define VFSHOOK_MS_IGNORE (MS_MOVE)
#else
#define VFSHOOK_MS_IGNORE (0)
#endif
    /* Interception housekeeping work: Patch filesystem?
       Do it only if the actual mount succeeded.
       We also ignore bind mounts and subtree moves. */
    if ( !err && !(flags & VFSHOOK_MS_IGNORE) )
    {
        dir = getname(dir_name);

        if ( !IS_ERR(dir) )
        {
            if ( !talpa_path_lookup(dir, TALPA_LOOKUP, &nd) )
            {
                path = talpa_alloc_path(&path_size);
                if ( path )
                {
                    /* Double path resolve. Makes smbmount way of mounting work. */
                    dir2 = d_path(nd.dentry, nd.mnt, path, path_size);
                    if ( !IS_ERR(dir2) )
                    {
                       if ( !talpa_path_lookup(dir2, TALPA_LOOKUP, &nd2) )
                       {
                            talpa_free_path(path);
                            path_release(&nd);
                            putname(dir);

                            processMount(nd2.mnt, flags, true);
                            path_release(&nd2);

                            return;
                        }
                    }

                    talpa_free_path(path);
                }

                path_release(&nd);
            }

            putname(dir);
        }

        err("Failed to synchronise post-mount!");
    }

    return;
}

static void talpaPreUmount(char* name, int flags)
{
    char* kname;
    struct patchedFilesystem *p;
    struct patchedFilesystem *patch = NULL;


    kname = getname(name);

    if ( !IS_ERR(kname) )
    {
        IFilesystemInfo *pFSInfo = GL_object.mLinuxFilesystemFactory->i_IFilesystemFactory.newFilesystemInfo(GL_object.mLinuxFilesystemFactory, EFS_Umount, NULL, kname, NULL);

        if ( likely(pFSInfo != NULL) )
        {
            if ( likely( (GL_object.mInterceptMask & HOOK_UMOUNT) != 0 ) )
            {
                GL_object.mTargetProcessor->examineFilesystemInfo(GL_object.mTargetProcessor, pFSInfo);
            }

            /* Assume umount will succeed and restore this fs */
            talpa_rcu_write_lock(&GL_object.mPatchLock);

            talpa_list_for_each_entry_rcu(p, &GL_object.mPatches, head)
            {
                if ( !strcmp(pFSInfo->type(pFSInfo->object), p->fstype->name) )
                {
                    patch = p;
                    dbg("Umount of %s (%s)", name, patch->fstype->name);
                    break;
                }
            }

            if ( patch )
            {
                if ( atomic_dec_and_test(&patch->usecnt) )
                {
                    restoreFilesystem(patch);
                    talpa_list_del_rcu(&patch->head);
                    talpa_rcu_write_unlock(&GL_object.mPatchLock);
                    atomic_dec(&patch->refcnt);
                    /* It is possible that the hook will keep the patch reference
                    for more than one rcu_synchronize call. To be safe, we will
                    keep synchronising until the refcnt drops to zero. */
                    do
                    {
                        talpa_rcu_synchronize();
                        dbg("PreUmount: refcnt for %s = %d after sync", patch->fstype->name, atomic_read(&patch->refcnt));
                    } while ( atomic_read(&patch->refcnt) > 0 );
                    talpa_free(patch);
                }
                else
                {
                    talpa_rcu_write_unlock(&GL_object.mPatchLock);
                }
                /* Free list showed to userspace so it will be regenerated on next read */
                destroyStringSet(&GL_object, &GL_object.mPatchListSet);
            }
            else
            {
                talpa_rcu_write_unlock(&GL_object.mPatchLock);
            }


            pFSInfo->delete(pFSInfo);
        }
        else
        {
            dbg("Failed to examine umount!");
        }

        putname(kname);
    }

    return;
}

static void talpaPostUmount(int err, char* name, int flags)
{
    char* kname;
    struct nameidata nd;
    struct patchedFilesystem *p;
    struct patchedFilesystem *patch = NULL;


    /* If the umount failed, we have to patch this fs again, but only if we think
       we managed to un-patch it in pre-mount, so we'll try to construct our objects.
       Yeah, this sucks, but currently I do not know of a better way... */
    if ( err )
    {
        kname = getname(name);

        if ( !IS_ERR(kname) )
        {
            IFilesystemInfo *pFSInfo = GL_object.mLinuxFilesystemFactory->i_IFilesystemFactory.newFilesystemInfo(GL_object.mLinuxFilesystemFactory, EFS_Umount, NULL, kname, NULL);

            if ( likely(pFSInfo != NULL) )
            {
                talpa_rcu_write_lock(&GL_object.mPatchLock);

                talpa_list_for_each_entry_rcu(p, &GL_object.mPatches, head)
                {
                    if ( !strcmp(pFSInfo->type(pFSInfo->object), p->fstype->name) )
                    {
                        patch = p;
                        break;
                    }
                }

                if ( patch )
                {
                    /* We have decremented usecnt in pre-mount */
                    atomic_inc(&patch->usecnt);
                    dbg("PostUmount: usecnt for %s = %d", patch->fstype->name, atomic_read(&patch->usecnt));
                    talpa_rcu_write_unlock(&GL_object.mPatchLock);
                }
                else
                {
                    /* We have completely restored this fs in pre-mount therefore we
                       must re-patch it. */
                    talpa_rcu_write_unlock(&GL_object.mPatchLock);

                    err = talpa_path_lookup(kname, LOOKUP_FOLLOW, &nd);

                    if ( !err )
                    {
                        err = processMount(nd.mnt, nd.mnt->mnt_flags, false);
                        path_release(&nd);
                    }
                    else
                    {
                        err("Mount point gone after umount failed!");
                    }
                }

                pFSInfo->delete(pFSInfo);
            }

            putname(kname);
        }
        else
        {
            err("Not enough memory to attempt re-patch after umount failed!");
        }
    }

    return;
}

static void walkMountTree(void)
{
    struct task_struct* inittask;
    struct vfsmount *rootmnt;
    struct vfsmount *mnt, *nextmnt;
    struct list_head *nexthead = NULL;


    talpa_tasklist_lock();
    inittask = find_task_by_pid(1);
    talpa_tasklist_unlock();

    if ( !inittask )
    {
        return;
    }

    read_lock(&inittask->fs->lock);
    spin_lock(&dcache_lock);
    talpa_vfsmount_lock();
    /* Find system root */
    for (rootmnt = inittask->fs->rootmnt; rootmnt != rootmnt->mnt_parent; rootmnt = rootmnt->mnt_parent);
    rootmnt = mntget(rootmnt);
    talpa_vfsmount_unlock();
    spin_unlock(&dcache_lock);
    read_unlock(&inittask->fs->lock);

    mnt = mntget(rootmnt);
    do
    {
        dbg("VFSMNT: 0x%p (at 0x%p), sb: 0x%p, dev: %s, fs: %s", mnt, mnt->mnt_parent, mnt->mnt_sb, mnt->mnt_devname, mnt->mnt_sb->s_type->name);

        processMount(mnt, mnt->mnt_flags, false);

        spin_lock(&dcache_lock);
        talpa_vfsmount_lock();

        /* Go down the tree for a child if there is one */
        if ( !list_empty(&mnt->mnt_mounts) )
        {
            nextmnt = list_entry(mnt->mnt_mounts.next, struct vfsmount, mnt_child);
        }
        else
        {
            nextmnt = mnt;
            /* If no children, go up until we found some. Abort on root. */
            while ( nextmnt != nextmnt->mnt_parent )
            {
                nexthead = nextmnt->mnt_child.next;
                /* Take next child if available */
                if ( nexthead != &nextmnt->mnt_parent->mnt_mounts )
                {
                    break;
                }
                /* Otherwise go up the tree */
                nextmnt = nextmnt->mnt_parent;
            }

            /* Abort if we are at the root */
            if ( nextmnt == nextmnt->mnt_parent )
            {
                mntput(mnt);
                talpa_vfsmount_unlock();
                spin_unlock(&dcache_lock);
                break;
            }

            /* Take next mount from the list */
            nextmnt = list_entry(nexthead, struct vfsmount, mnt_child);
        }

        mntget(nextmnt);
        mntput(mnt);
        mnt = nextmnt;
        talpa_vfsmount_unlock();
        spin_unlock(&dcache_lock);
    } while (mnt);

    mntput(rootmnt);
}

/*
 * Object creation/destruction.
 */
static char *skip_list = "";
static char *no_scan = "";

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
module_param(skip_list, charp, 0400);
module_param(no_scan, charp, 0400);
#else
MODULE_PARM(skip_list, "s");
MODULE_PARM(no_scan, "s");
#endif
MODULE_PARM_DESC(skip_list, "Comma-delimited list of additions/removals from the list of ignored filesystems");
MODULE_PARM_DESC(no_scan, "Comma-delimited list of additions/removals from the list of filesystems which need a workaround on mount");

static void parseParams(void* self, char *param, talpa_list_head* list, char **set)
{
    VFSHookObject *obj, *tmp;
    char* token;
    char* delimiter;


    if ( strlen(param) < 2 )
    {
        return;
    }

    if ( !strcmp(param, "none") )
    {
        talpa_list_for_each_entry_safe(obj, tmp, list, head)
        {
            if ( !obj->protected )
            {
                talpa_list_del(&obj->head);
                freeObject(obj);
            }
        }

        return;
    }

    /* Tokenize string with ',' as a delimiter */
    token = param;
next_token:
    delimiter = strchr(token, ',');
    if ( !delimiter )
    {
        doActionString(this, list, set, token);
    }
    else
    {
        *delimiter = 0;
        doActionString(this, list, set, token);
        token = ++delimiter;
        goto next_token;
    }
}

static void purgePatches(void* self)
{
    struct patchedFilesystem *p;

nextpatch:
    talpa_rcu_write_lock(&this->mPatchLock);
    talpa_list_for_each_entry_rcu(p, &this->mPatches, head)
    {
        dbg("Restoring %s", p->fstype->name);
        restoreFilesystem(p);
        talpa_list_del_rcu(&p->head);
        talpa_rcu_write_unlock(&this->mPatchLock);
        atomic_dec(&p->refcnt);
        do
        {
            talpa_rcu_synchronize();
            dbg("purgePatches: refcnt for %s = %d after sync", p->fstype->name, atomic_read(&p->refcnt));
        } while ( atomic_read(&p->refcnt) > 0 );
        talpa_free(p);
        goto nextpatch;
    }
    talpa_rcu_write_unlock(&this->mPatchLock);
}

VFSHookInterceptor* newVFSHookInterceptor(void)
{
    VFSHookObject *obj, *tmp;


    talpa_mutex_lock(&GL_object.mSemaphore);

    if ( GL_object.mInitialized )
    {
        talpa_mutex_unlock(&GL_object.mSemaphore);
        err("Duplicate initialization attempted!");
        return NULL;
    }

    init_waitqueue_head(&GL_object.mUnload);

    constructSpecialSet(&GL_object);
    GL_object.mLinuxFilesystemFactory = TALPA_Portability()->filesystemFactory()->object;
    GL_object.mLinuxSystemRoot = TALPA_Portability()->systemRoot()->object;

    talpa_rcu_lock_init(&GL_object.mPatchLock);
    TALPA_INIT_LIST_HEAD(&GL_object.mPatches);
    talpa_rcu_lock_init(&GL_object.mListLock);
    TALPA_INIT_LIST_HEAD(&GL_object.mSkipFilesystems);
    TALPA_INIT_LIST_HEAD(&GL_object.mNoScanFilesystems);

    /* Configure the interceptor with platform dependent data */
    appendObject(&GL_object, &GL_object.mSkipFilesystems, "rootfs", true);
    appendObject(&GL_object, &GL_object.mSkipFilesystems, "proc", false);
    appendObject(&GL_object, &GL_object.mSkipFilesystems, "usbfs", false);
    appendObject(&GL_object, &GL_object.mSkipFilesystems, "devpts", false);
    appendObject(&GL_object, &GL_object.mSkipFilesystems, "devfs", false);
    appendObject(&GL_object, &GL_object.mSkipFilesystems, "subfs", true);
    appendObject(&GL_object, &GL_object.mSkipFilesystems, "nfsd", false);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
    appendObject(&GL_object, &GL_object.mSkipFilesystems, "sysfs", false);
    appendObject(&GL_object, &GL_object.mSkipFilesystems, "debugfs", false);
    appendObject(&GL_object, &GL_object.mSkipFilesystems, "securityfs", false);
#else
    appendObject(&GL_object, &GL_object.mSkipFilesystems, "usbdevfs", false);
#endif
    appendObject(&GL_object, &GL_object.mSkipFilesystems, "nssadmin", true);
    appendObject(&GL_object, &GL_object.mSkipFilesystems, "nsspool", true);

    appendObject(&GL_object, &GL_object.mNoScanFilesystems, "smbfs", true);
    appendObject(&GL_object, &GL_object.mNoScanFilesystems, "fuse", true);

    /* Parse module parameters */
    parseParams(&GL_object, skip_list, &GL_object.mSkipFilesystems, &GL_object.mSkipFilesystemsSet);
    parseParams(&GL_object, no_scan, &GL_object.mNoScanFilesystems, &GL_object.mNoScanFilesystemsSet);

    /* Lock kernel so that no (u)mounting can happen between us walking the mount
       tree and hooking into the syscall table */
    lock_kernel();

    /* See which filesystem are already present and patch them */
    walkMountTree();

    /* Start catching (u)mounts to hook new filesystems */
    if ( talpa_syscallhook_register(&GL_object.mSyscallOps) )
    {
        unlock_kernel();
        purgePatches(&GL_object);
        /* Free the configuration list objects */
        talpa_list_for_each_entry_safe(obj, tmp, &GL_object.mSkipFilesystems, head)
        {
            talpa_list_del(&obj->head);
            freeObject(obj);
        }
        talpa_list_for_each_entry_safe(obj, tmp, &GL_object.mNoScanFilesystems, head)
        {
            talpa_list_del(&obj->head);
            freeObject(obj);
        }
        talpa_mutex_unlock(&GL_object.mSemaphore);
        err("Failed to register with talpa-syscallhook!");
        return NULL;
    }

    unlock_kernel();

    GL_object.mInitialized = true;

    talpa_mutex_unlock(&GL_object.mSemaphore);

    return &GL_object;
}

static void deleteVFSHookInterceptor(struct tag_VFSHookInterceptor* object)
{
    VFSHookObject *obj, *tmp;


    dbg("destructor");

    talpa_mutex_lock(&object->mSemaphore);

    if ( !object->mInitialized )
    {
        talpa_mutex_unlock(&object->mSemaphore);
        err("Tried to delete before initializing!");
        return;
    }

    talpa_syscallhook_unregister(&object->mSyscallOps);

    if ( object->mInterceptMask )
    {
        object->mInterceptMask = 0;
        strcpy(object->mConfigData.value, CFG_VALUE_DISABLED);
    }

    object->mInitialized = false;

    talpa_mutex_unlock(&object->mSemaphore);

    purgePatches(object);

    /* Now we must wait for all callers to leave our hooks */
    wait_event(object->mUnload, atomic_read(&object->mUseCnt) == 0);

    object->mLinuxFilesystemFactory = NULL;
    object->mLinuxSystemRoot = NULL;

    /* Free the configuration list objects */
    talpa_list_for_each_entry_safe(obj, tmp, &object->mSkipFilesystems, head)
    {
        talpa_list_del(&obj->head);
        freeObject(obj);
    }
    talpa_list_for_each_entry_safe(obj, tmp, &object->mNoScanFilesystems, head)
    {
        talpa_list_del(&obj->head);
        freeObject(obj);
    }

    /* Free string sets representing configuration data */
    talpa_free(object->mSkipFilesystemsSet);
    talpa_free(object->mNoScanFilesystemsSet);
    talpa_free(object->mPatchListSet);

    return;
}

/*
 * configuration list handling & objects
 */

static VFSHookObject* newObject(void *self, const char* string, bool protected)
{
    VFSHookObject* obj = NULL;

    obj = talpa_alloc(sizeof(VFSHookObject));

    if ( obj )
    {
        TALPA_INIT_LIST_HEAD(&obj->head);
        obj->len = strlen(string);
        obj->value = talpa_alloc(obj->len + 1);
        obj->protected = protected;
        if ( !obj->value )
        {
            talpa_free(obj);
            return NULL;
        }
        strcpy(obj->value, string);
    }

    return obj;
}

static void freeObject(VFSHookObject* obj)
{
    talpa_free(obj->value);
    talpa_free(obj);

    return;
}

static void deleteObject(void *self, VFSHookObject* obj)
{
    talpa_rcu_synchronize();
    freeObject(obj);

    return;
}

static void constructStringSet(void* self, talpa_list_head* list, char** set)
{
    unsigned int len;
    unsigned int alloc_len = 0;
    VFSHookObject* obj;
    char* newset = NULL;
    char* out;


    /* We are doing the allocation in at least 2-passes.
     * That is because we want to allocate enough storage outside of
     * the lock holding section. */
try_alloc:
    /* We do not allocate anything in first pass. */
    if ( alloc_len )
    {
        newset = talpa_alloc(alloc_len);
        if ( !newset )
        {
            err("Failed to create string set!");
            return;
        }
    }

    len = 0;
    talpa_rcu_read_lock(&this->mListLock);
    talpa_list_for_each_entry_rcu(obj, list, head)
    {
        len += 1 + obj->len + 1;
    }

    /* We will reallocate if the size has increased or this is a second pass (first allocation)/ */
    if ( (len + 1) > alloc_len )
    {
        talpa_rcu_read_unlock(&this->mListLock);
        alloc_len = len + 1;
        talpa_free(newset);
        goto try_alloc;
    }

    out = newset;
    talpa_free(*set);
    talpa_list_for_each_entry_rcu(obj, list, head)
    {
        if ( obj->protected )
        {
            *out++ = '!';
        }
        strcpy(out, obj->value);
        out += obj->len;
        *out++ = '\n';
    }
    if ( out > newset )
    {
        out--;
    }
    *out = 0;
    *set = newset;

    talpa_rcu_read_unlock(&this->mListLock);

    return;
}

static void constructPatchListSet(const void* self)
{
    unsigned int len;
    unsigned int alloc_len = 0;
    struct patchedFilesystem* patch;
    char* newset = NULL;
    char* out;
    char fss;
    int ret;


    /* We are doing the allocation in at least 2-passes.
     * That is because we want to allocate enough storage outside of
     * the lock holding section. */
try_alloc:
    /* We do not allocate anything in first pass. */
    if ( alloc_len )
    {
        newset = talpa_alloc(alloc_len);
        if ( !newset )
        {
            err("Failed to create string set!");
            return;
        }
    }

    len = 0;
    talpa_rcu_read_lock(&this->mPatchLock);
    talpa_list_for_each_entry_rcu(patch, &this->mPatches, head)
    {
        /* Output line format: fsname refcnt usecnt f|i|s */
        len += strlen(patch->fstype->name) + 1 + 10 + 1 + 1 + 1;
    }

    /* We will reallocate if the size has increased or this is a second pass (first allocation)/ */
    if ( (len + 1) > alloc_len )
    {
        talpa_rcu_read_unlock(&this->mPatchLock);
        alloc_len = len + 1;
        talpa_free(newset);
        goto try_alloc;
    }

    out = newset;
    talpa_free(this->mPatchListSet);
    talpa_list_for_each_entry_rcu(patch, &this->mPatches, head)
    {
        if ( patch->f_ops )
        {
            fss = 'F';
        }
        else if ( patch->sf_ops )
        {
            fss = 'S';
        }
        else if ( patch->i_ops )
        {
            fss = 'I';
        }
        else
        {
            fss = '?';
        }
        if ( atomic_read(&patch->usecnt) > 0xffffffff )
        {
            ret = sprintf(out, "%s x %c\n", patch->fstype->name, fss);
        }
        else
        {
            ret = sprintf(out, "%s %u %c\n", patch->fstype->name, atomic_read(&patch->usecnt), fss);
        }
        if ( ret > 0 )
        {
            out += ret;
        }
    }
    if ( out > newset )
    {
        out--;
    }
    *out = 0;
    this->mPatchListSet = newset;

    talpa_rcu_read_unlock(&this->mPatchLock);

    return;
}

static void destroyStringSet(void *self, char **set)
{
    talpa_free(*set);
    *set = NULL;
    return;
}

static VFSHookObject* findObject(const void* self, talpa_list_head* list, const char* value)
{
    VFSHookObject *obj;

    talpa_list_for_each_entry_rcu(obj, list, head)
    {
        if ( !strcmp(obj->value, value) )
        {
            return obj;
        }
    }

    return NULL;
}

static VFSHookObject* appendObject(void* self, talpa_list_head* list, const char* value, bool protected)
{
    VFSHookObject *obj;


    talpa_rcu_read_lock(&this->mListLock);
    obj = findObject(this, list, value);
    talpa_rcu_read_unlock(&this->mListLock);
    if ( obj )
    {
        dbg("String already in list!");
        return obj;
    }
    /* No problem here since appends and removes happen from userspace
     * which is serialised. */
    obj = newObject(this, value, protected);
    if ( obj )
    {
        talpa_rcu_write_lock(&this->mListLock);
        talpa_list_add_tail_rcu(&obj->head, list);
        talpa_rcu_write_unlock(&this->mListLock);
    }

    return obj;
}

static bool removeObject(void *self, talpa_list_head* list, const char* value)
{
    VFSHookObject *obj;


    talpa_rcu_write_lock(&this->mListLock);
    obj = findObject(this, list, value);
    if ( obj && !obj->protected )
    {
        talpa_list_del_rcu(&obj->head);
        talpa_rcu_write_unlock(&this->mListLock);
        deleteObject(this, obj);
        return true;
    }
    talpa_rcu_write_unlock(&this->mListLock);

    return false;
}

static void doActionString(void* self, talpa_list_head* list, char** set, const char* value)
{
    if ( strlen(value) < 2 )
    {
        return;
    }

    if ( value[0] == '+')
    {
        if ( (value[1] == '!') && (strlen(value) > 2) )
        {
            appendObject(this, list, &value[2], true);
        }
        else
        {
            appendObject(this, list, &value[1], false);
        }
    }
    else if ( value[0] == '-' )
    {
        removeObject(this, list, &value[1]);
    }

    destroyStringSet(this, set);

    return;
}

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
    if ( this->mInterceptMask )
    {
        this->mInterceptMask = 0;
        strcpy(this->mConfigData.value, CFG_VALUE_DISABLED);
        atomic_dec(&this->mUseCnt);
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
    return "VFSHookInterceptor";
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
        char* retstring = cfgElement->value;

        talpa_mutex_lock(&this->mSemaphore);

        if ( !strcmp(cfgElement->name, CFG_FS) )
        {
            if ( !this->mSkipFilesystemsSet )
            {
                constructStringSet(this, &this->mSkipFilesystems, &this->mSkipFilesystemsSet);
            }
            retstring = this->mSkipFilesystemsSet;
        }
        else if ( !strcmp(cfgElement->name, CFG_NOSCAN) )
        {
            if ( !this->mNoScanFilesystemsSet )
            {
                constructStringSet(this, &this->mNoScanFilesystems, &this->mNoScanFilesystemsSet);
            }
            retstring = this->mNoScanFilesystemsSet;
        }
        else if ( !strcmp(cfgElement->name, CFG_PATCHLIST) )
        {
            if ( !this->mPatchListSet )
            {
                constructPatchListSet(this);
            }
            retstring = this->mPatchListSet;
        }

        talpa_mutex_unlock(&this->mSemaphore);

        return retstring;
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
    else if ( !strcmp(name, CFG_FS) )
    {
        doActionString(this, &this->mSkipFilesystems, &(this->mSkipFilesystemsSet), value);
    }
    else if ( !strcmp(name, CFG_NOSCAN) )
    {
        doActionString(this, &this->mNoScanFilesystems, &(this->mNoScanFilesystemsSet), value);
    }

    talpa_mutex_unlock(&this->mSemaphore);

    return;
}

/*
 * End of vfshook_interceptor.c
 */
