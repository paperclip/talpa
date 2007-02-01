
/*
* linux_file.c
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
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/smp_lock.h>
#if defined TALPA_INODE_USES_MUTEXES
#include <linux/mutex.h>
#else
#include <asm/semaphore.h>
#endif

#include "common/talpa.h"
#include "linux_file.h"



/*
* Forward declare implementation methods.
*/
static void    get          (void* self);
static int     open         (void* self, const char* filename, unsigned int flags, unsigned int mode);
static int     openExec     (void* self, const char* filename);
static int     openInternal (void* self, void* dentry, unsigned int flags);
static bool    isOpen       (const void* self);
static bool    isWritable   (const void* self);
static int     close        (void* self);
static loff_t  length       (const void* self);
static loff_t  seek         (void* self, loff_t offset, int whence);
static ssize_t read         (void* self, void* data, size_t count);
static ssize_t write        (void* self, const void* data, size_t count);
static int     unlink       (void* self);
static int     truncate     (void* self, loff_t length);

static void deleteLinuxFile(struct tag_LinuxFile* object);

/*
* Template Object.
*/
static LinuxFile template_LinuxFile =
    {
        {
            get,
            open,
            openExec,
            openInternal,
            isOpen,
            isWritable,
            close,
            length,
            seek,
            read,
            write,
            unlink,
            truncate,
            NULL,
            (void (*)(void*))deleteLinuxFile
        },
        deleteLinuxFile,
        ATOMIC_INIT(1),
        Regular,
        false,
        NULL,
        NULL,
        0
    };
#define this    ((LinuxFile*)self)


/*
* Object creation/destruction.
*/
LinuxFile* newLinuxFile(void)
{
    LinuxFile* object;


    object = kmalloc(sizeof(template_LinuxFile), SLAB_KERNEL);
    if ( likely(object != NULL) )
    {
        memcpy(object, &template_LinuxFile, sizeof(template_LinuxFile));
        object->i_IFile.object = object;
    }
    return object;
}

static inline bool verifyFile(struct file* file)
{
    if ( file->f_dentry && file->f_dentry->d_inode && S_ISREG(file->f_dentry->d_inode->i_mode) )
    {
        return true;
    }

    return false;
}

LinuxFile* cloneLinuxFile(struct file* fobject)
{
    LinuxFile* object;
    loff_t offset;


    if ( !verifyFile(fobject) )
    {
        return NULL;
    }

    object = kmalloc(sizeof(template_LinuxFile), SLAB_KERNEL);
    if ( likely(object != NULL) )
    {
        memcpy(object, &template_LinuxFile, sizeof(template_LinuxFile));
        object->i_IFile.object = object;

        object->mOpenType = Cloned;

        get_file(fobject);

        if ( fobject->f_flags & (O_WRONLY | O_RDWR) )
        {
            object->mWritable = true;
        }

        object->mFile = fobject;
        object->mFiles = current->files;

        offset = seek(object, 0, 1);
        if ( unlikely(offset < 0) )
        {
            kfree(object);
            return NULL;
        }

        object->mOffset = offset;
    }
    return object;
}

static void deleteLinuxFile(struct tag_LinuxFile* object)
{
    if ( atomic_dec_and_test(&object->mRefCnt) )
    {
        close(object);
        kfree(object);
    }

    return;
}

/*
* IFile.
*/

static void get(void* self)
{
    atomic_inc(&this->mRefCnt);
    return;
}

static int open(void* self, const char* filename, unsigned int flags, unsigned int mode)
{
    struct file* file;


    if ( unlikely(this->mFile != NULL) )
    {
        return -EBUSY;
    }

    file = filp_open(filename, flags, mode);

    if ( unlikely(IS_ERR(file)) )
    {
        return PTR_ERR(file);
    }

    if ( !verifyFile(file) )
    {
        filp_close(file, current->files);
        return -EBADF;
    }

    if ( flags & (O_WRONLY | O_RDWR) )
    {
        this->mWritable = true;
    }

    this->mOpenType = Regular;
    this->mFile = file;
    this->mFiles = current->files;
    this->mOffset = 0;

    return 0;
}

static int openExec(void* self, const char* filename)
{
    struct file* file;


    if ( unlikely(this->mFile != NULL) )
    {
        return -EBUSY;
    }

    file = open_exec(filename);

    if ( unlikely(IS_ERR(file)) )
    {
        return PTR_ERR(file);
    }

    this->mOpenType = Exec;
    this->mFile = file;
    this->mFiles = current->files;
    this->mOffset = 0;

    return 0;
}

static int openInternal(void* self, void* dentry, unsigned int flags)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)) || (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,7))
    return -ENOSYS;
#else
    int ret;
    struct file* file;

    file = get_empty_filp();

    if ( !file )
    {
        return -EMFILE;
    }

    ret = open_private_file(file, (struct dentry *)dentry, flags);

    if ( ret )
    {
        put_filp(file);
    }
    else
    {
        if ( flags & (O_WRONLY | O_RDWR) )
        {
            this->mWritable = true;
        }

        this->mOpenType = Internal;
        this->mFile = file;
        this->mFiles = NULL;
        this->mOffset = 0;
    }

    return 0;
#endif
}

static bool isOpen(const void* self)
{
    if ( this->mFile )
    {
        return true;
    }

    return false;
}

static bool isWritable(const void* self)
{
    return this->mWritable;
}

static int close(void* self)
{
    int retval = 0;


    if ( unlikely(!this->mFile) )
    {
        return -EBADF;
    }

    switch ( this->mOpenType )
    {
        case Exec:
            allow_write_access(this->mFile);
            /* Intentional fall-through! */
        case Regular:
            retval = filp_close(this->mFile, this->mFiles);
            break;
        case Cloned:
            retval = seek(this, this->mOffset, 0);
            atomic_dec(&this->mFile->f_count);
            break;
        case Internal:
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)) && (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,8))
            close_private_file(this->mFile);
            put_filp(this->mFile);
#endif
            break;
    }

    this->mFile = NULL;
    this->mFiles = NULL;
    this->mOffset = 0;

    return retval;
}

static loff_t length(const void* self)
{
    if ( unlikely(!this->mFile) )
    {
        return -EBADF;
    }

    return this->mFile->f_dentry->d_inode->i_size;
}

static loff_t seek(void* self, loff_t offset, int whence)
{
    struct file* file = this->mFile;
    mm_segment_t oldfs;
    loff_t res;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,8)
    loff_t (*fn)(struct file *, loff_t, int);
#endif

    if ( unlikely(!file) )
    {
        return -EBADF;
    }

    res = -EINVAL;

    if ( whence > 2 )
    {
        return res;
    }

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    fn = default_llseek;
    if (file->f_op && file->f_op->llseek)
        fn = file->f_op->llseek;
    oldfs = get_fs(); set_fs(KERNEL_DS);
    lock_kernel();
    res = fn(file, offset, whence);
    unlock_kernel();
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,8)
    fn = default_llseek;
    if (file->f_op && file->f_op->llseek)
        fn = file->f_op->llseek;
    oldfs = get_fs(); set_fs(KERNEL_DS);
    res = fn(file, offset, whence);
#else
    oldfs = get_fs(); set_fs(KERNEL_DS);
    res = vfs_llseek(file, offset, whence);
#endif
    set_fs(oldfs);

    return res;
}

static ssize_t read(void* self, void* data, size_t count)
{
    struct file* file;
    mm_segment_t oldfs;
    ssize_t retval;


    if ( unlikely(!this->mFile) )
    {
        return -EBADF;
    }

    file = this->mFile;

    if ( !file->f_op || !file->f_op->read )
    {
        return -EINVAL;
    }

    oldfs = get_fs(); set_fs(KERNEL_DS);
    retval = file->f_op->read(file, data, count, &file->f_pos);
    set_fs(oldfs);

    return retval;
}

static ssize_t write(void* self, const void* data, size_t count)
{
    struct file* file;
    mm_segment_t oldfs;
    ssize_t retval;


    if ( unlikely(!this->mFile) )
    {
        return -EBADF;
    }

    file = this->mFile;

    if ( !file->f_op || !file->f_op->write )
    {
        return -EINVAL;
    }

    oldfs = get_fs(); set_fs(KERNEL_DS);
    retval = file->f_op->write(file, data, count, &file->f_pos);
    set_fs(oldfs);

    return retval;
}

static int unlink(void* self)
{
    int error;
    struct dentry* parentd;
    struct inode* parenti;
    struct dentry* filed;


    if ( unlikely(!this->mFile) )
    {
        return -EBADF;
    }

    filed = dget(this->mFile->f_dentry);

    if ( S_ISDIR(filed->d_inode->i_mode) )
    {
        return -EISDIR;
    }

    parentd = dget(filed->d_parent);

    if ( !parentd )
    {
        dput(filed);
        return -ENOTDIR;
    }

    parenti = parentd->d_inode;

    if ( !parenti )
    {
        dput(parentd);
        dput(filed);
        return -ENOENT;
    }

#if defined TALPA_INODE_USES_MUTEXES
    mutex_lock(&parenti->i_mutex);
#else
    down(&parenti->i_sem);
#endif
    atomic_inc(&parenti->i_count);
    error = vfs_unlink(parenti, filed);
#if defined TALPA_INODE_USES_MUTEXES
    mutex_unlock(&parenti->i_mutex);
#else
    up(&parenti->i_sem);
#endif
    iput(parenti);
    dput(parentd);
    dput(filed);

    return error;
}

static int truncate(void* self, loff_t length)
{
    /*
     * Following code is taken from kernel sources and modified.
     */

    struct inode * inode;
    struct dentry *dentry;
    struct file * file;
    int error;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,13)
    int small = 1;
#endif

    error = -EINVAL;
    if (length < 0)
        goto out;
    error = -EBADF;
    file = this->mFile;
    if (!file)
        goto out;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,13)
    /* explicitly opened as large or we are on 64-bit box */
    if (file->f_flags & O_LARGEFILE)
        small = 0;
#endif

    dentry = file->f_dentry;
    inode = dentry->d_inode;
    error = -EINVAL;
    if (!S_ISREG(inode->i_mode) || !(file->f_mode & FMODE_WRITE))
        goto out;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,13)
    error = -EINVAL;
    /* Cannot ftruncate over 2^31 bytes without large file support */
    if (small && length > MAX_NON_LFS)
        goto out;

    error = -EPERM;
    if (IS_APPEND(inode))
        goto out;
#else
    error = -EPERM;
    if (IS_IMMUTABLE(inode) || IS_APPEND(inode))
        goto out;
#endif

    error = locks_verify_truncate(inode, file, length);
    if (!error) {
        struct iattr newattrs;

        /* Not pretty: "inode->i_size" shouldn't really be signed. But it is. */
        if (length < 0)
            error = -EINVAL;
        else {
            newattrs.ia_size = length;
            newattrs.ia_valid = ATTR_SIZE | ATTR_CTIME;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,15)
            newattrs.ia_file = file;
            newattrs.ia_valid |= ATTR_FILE;
#endif
#if defined TALPA_INODE_USES_MUTEXES
            mutex_lock(&inode->i_mutex);
#else
            down(&inode->i_sem);
#endif
/* inode->i_alloc_sem appears starting with 2.4.22 */
#if     (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0) && LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,22)) \
    ||  (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0) && LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,6) && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11) ) \
    ||  defined TALPA_HAS_INODE_ALLOC_SEM
            down_write(&inode->i_alloc_sem);
#endif
            error = notify_change(dentry, &newattrs);
#if     (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0) && LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,22)) \
    ||  (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0) && LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,6) && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11)) \
    ||  defined TALPA_HAS_INODE_ALLOC_SEM
            up_write(&inode->i_alloc_sem);
#endif
#if defined TALPA_INODE_USES_MUTEXES
            mutex_unlock(&inode->i_mutex);
#else
            up(&inode->i_sem);
#endif
        }
    }

    out:
    return error;
}

/*
* End of linux_file.c
*/
