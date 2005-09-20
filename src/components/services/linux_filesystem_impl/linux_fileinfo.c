/*
* linux_fileinfo.c
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

#include <linux/slab.h>
#include <linux/string.h>
#include <asm/uaccess.h>
#include <linux/file.h>

#include "common/talpa.h"
#include "filesystem/isystemroot.h"
#include "platforms/linux/glue.h"
#include "linux_fileinfo.h"
#include "app_ctrl/iportability_app_ctrl.h"


/*
* Forward declare implementation methods.
*/
static void                  get                (const void* self);
static EFilesystemOperation  operation          (const void* self);
static const char*           filename           (const void* self);
static unsigned int          flags              (const void* self);
static unsigned int          mode               (const void* self);
static unsigned long         inode              (const void* self);
static bool                  isWritable         (const void* self);
static bool                  isWritableAnywhere (const void* self);
static uint64_t              device             (const void* self);
static uint32_t              deviceMajor        (const void* self);
static uint32_t              deviceMinor        (const void* self);
static const char*           deviceName         (const void* self);
static const char*           fsType             (const void* self);
static void deleteLinuxFileInfo(struct tag_LinuxFileInfo* object);


/*
* Template Object.
*/
static LinuxFileInfo template_LinuxFileInfo =
    {
        {
            get,
            operation,
            filename,
            flags,
            mode,
            inode,
            isWritable,
            isWritableAnywhere,
            device,
            deviceMajor,
            deviceMinor,
            deviceName,
            fsType,
            0,
            (void (*)(const void*))deleteLinuxFileInfo
        },
        deleteLinuxFileInfo,
        ATOMIC_INIT(1),
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0
    };
#define this    ((LinuxFileInfo*)self)


/*
* Object creation/destruction.
*/
LinuxFileInfo* newLinuxFileInfo(EFilesystemOperation operation, const char* filename, int flags, int mode)
{
    LinuxFileInfo* object;


    object = kmalloc(sizeof(template_LinuxFileInfo), SLAB_KERNEL);
    if ( likely(object != 0) )
    {
        struct nameidata nd;
        int rc;


        memcpy(object, &template_LinuxFileInfo, sizeof(template_LinuxFileInfo));
        object->i_IFileInfo.object = object;

        if ( likely((rc = talpa_path_lookup(filename, TALPA_LOOKUP, &nd)) == 0 ) )
        {
            object->mPage = (char *)__get_free_page(GFP_KERNEL);
            if ( likely(object->mPage != NULL) )
            {
                ISystemRoot* root = TALPA_Portability()->systemRoot();

                object->mFilename = talpa_d_path(nd.dentry, nd.mnt, root->directoryEntry(root->object), root->mountPoint(root->object), object->mPage, PAGE_SIZE);
                object->mOperation = operation;
                object->mFlags = flags;
                object->mMode = nd.dentry->d_inode->i_mode;
                object->mIno = nd.dentry->d_inode->i_ino;
                object->mVFSMount = mntget(nd.mnt);
                object->mWriteCount = atomic_read(&nd.dentry->d_inode->i_writecount);
                object->mDevice = kdev_t_to_nr(inode_dev(nd.dentry->d_inode));
                object->mDeviceMajor = MAJOR(inode_dev(nd.dentry->d_inode));
                object->mDeviceMinor = MINOR(inode_dev(nd.dentry->d_inode));
//                 dbg("%s, F:0x%x, M:0x%x, D:0x%x",object->mFilename,object->mFlags,object->mMode,(unsigned int)object->mDevice);
            }
            else
            {
                kfree(object);
                warn("Not getting a single free page!");
                path_release(&nd);

                return NULL;
            }

            path_release(&nd);
        }
        else
        {
            kfree(object);

            return NULL;
        }
    }
    return object;
}

LinuxFileInfo* newLinuxFileInfoFromFd(EFilesystemOperation operation, int fd)
{
    LinuxFileInfo* object;


    object = kmalloc(sizeof(template_LinuxFileInfo), SLAB_KERNEL);
    if ( likely(object != 0) )
    {
        struct file *file;


        memcpy(object, &template_LinuxFileInfo, sizeof(template_LinuxFileInfo));
        object->i_IFileInfo.object = object;

        object->mPage = (char *)__get_free_page(GFP_KERNEL);
        if ( unlikely(!object->mPage) )
        {
            kfree(object);
            warn("Not getting a single free page!");

            return NULL;
        }
        file = fget(fd);
        if ( likely(file != NULL) )
        {
            ISystemRoot* root = TALPA_Portability()->systemRoot();

            object->mFilename = talpa_d_path(file->f_dentry, file->f_vfsmnt, root->directoryEntry(root->object), root->mountPoint(root->object), object->mPage, PAGE_SIZE);
            object->mOperation = operation;
            object->mFlags = file->f_flags;
            object->mVFSMount = mntget(file->f_vfsmnt);

            if ( likely(file->f_dentry && file->f_dentry->d_inode) )
            {
                object->mMode = file->f_dentry->d_inode->i_mode;
                object->mIno = file->f_dentry->d_inode->i_ino;
                object->mInode = file->f_dentry->d_inode;
                object->mDevice = kdev_t_to_nr(inode_dev(file->f_dentry->d_inode));
                object->mDeviceMajor = MAJOR(inode_dev(file->f_dentry->d_inode));
                object->mDeviceMinor = MINOR(inode_dev(file->f_dentry->d_inode));
            }
            else
            {
                dbg("NO DENTRY/INODE!");
            }
//             dbg("%s, F:0x%x, M:0x%x, D:0x%x",object->mFilename,object->mFlags,object->mMode,(unsigned int)object->mDevice);
            fput(file);
        }
        else
        {
            free_page((unsigned long)object->mPage);
            kfree(object);
//             dbg("File structure for %d gone in %s[%u]!",fd,current->comm,current->pid);

            return NULL;
        }
    }

    return object;
}

LinuxFileInfo* newLinuxFileInfoFromFile(EFilesystemOperation operation, void* fileobj)
{
    LinuxFileInfo* fi;
    struct file *file;
    struct inode* inode;
    ISystemRoot* root;


    file = (struct file *)fileobj;

    if ( unlikely((file->f_dentry == NULL) || (file->f_vfsmnt == NULL)) )
    {
        return NULL;
    }

    fi = kmalloc(sizeof(template_LinuxFileInfo), SLAB_KERNEL);
    if ( unlikely(fi == NULL) )
    {
        err("Not enought memory for a file info object!");
        return NULL;
    }

    memcpy(fi, &template_LinuxFileInfo, sizeof(template_LinuxFileInfo));
    fi->i_IFileInfo.object = fi;

    fi->mPage = (char *)__get_free_page(GFP_KERNEL);
    if ( unlikely(!fi->mPage) )
    {
        kfree(fi);
        warn("Not getting a single free page!");

        return NULL;
    }

    inode = file->f_dentry->d_inode;
    root = TALPA_Portability()->systemRoot();

    fi->mFilename = talpa_d_path(file->f_dentry, file->f_vfsmnt, root->directoryEntry(root->object), root->mountPoint(root->object), fi->mPage, PAGE_SIZE);
    fi->mOperation = operation;
    fi->mFlags = file->f_flags;
    fi->mMode = inode->i_mode;
    fi->mIno = inode->i_ino;
    fi->mInode = inode;
    fi->mVFSMount = mntget(file->f_vfsmnt);
    fi->mDevice = kdev_t_to_nr(inode_dev(inode));
    fi->mDeviceMajor = MAJOR(inode_dev(inode));
    fi->mDeviceMinor = MINOR(inode_dev(inode));

    return fi;
}

LinuxFileInfo* newLinuxFileInfoFromDirectoryEntry(EFilesystemOperation operation, void* dentryobj, void* mntobj, int flags, int mode)
{
    LinuxFileInfo* fi;
    struct dentry* dentry;
    struct inode* inode;
    struct vfsmount* vfsmnt;
    ISystemRoot* root;


    if ( unlikely( !dentryobj || !mntobj ) )
    {
        err("Constructor called with insufficient data!");
        return NULL;
    }

    fi = kmalloc(sizeof(template_LinuxFileInfo), SLAB_KERNEL);
    if ( unlikely(fi == NULL) )
    {
        err("Not enought memory for a file info object!");
        return NULL;
    }

    memcpy(fi, &template_LinuxFileInfo, sizeof(template_LinuxFileInfo));
    fi->i_IFileInfo.object = fi;

    fi->mPage = (char *)__get_free_page(GFP_KERNEL);
    if ( unlikely(!fi->mPage) )
    {
        kfree(fi);
        warn("Not getting a single free page!");

        return NULL;
    }

    dentry = (struct dentry *)dentryobj;
    inode = dentry->d_inode;
    vfsmnt = (struct vfsmount *)mntobj;
    root = TALPA_Portability()->systemRoot();

    fi->mFilename = talpa_d_path(dentry, vfsmnt, root->directoryEntry(root->object), root->mountPoint(root->object), fi->mPage, PAGE_SIZE);
    fi->mOperation = operation;
    fi->mFlags = flags;
    fi->mVFSMount = mntget(vfsmnt);

    if ( unlikely( mode > 0 ) )
    {
        fi->mMode = mode;
    }
    else if ( likely( inode != NULL ) )
    {
        fi->mMode = inode->i_mode;
    }

    if ( likely(inode != NULL) )
    {
        fi->mIno = inode->i_ino;
        fi->mInode = inode;
        fi->mDevice = kdev_t_to_nr(inode_dev(inode));
        fi->mDeviceMajor = MAJOR(inode_dev(inode));
        fi->mDeviceMinor = MINOR(inode_dev(inode));
    }

    return fi;
}

LinuxFileInfo* newLinuxFileInfoFromInode(EFilesystemOperation operation, void* inodeobj, int flags)
{
    LinuxFileInfo* fi;
    struct inode* inode = (struct inode*)inodeobj;

    if ( unlikely( inode == NULL ) )
    {
        err("No inode in constructor!");
        return NULL;
    }

    fi = kmalloc(sizeof(template_LinuxFileInfo), SLAB_KERNEL);
    if ( unlikely(fi == NULL) )
    {
        err("Not enought memory for a file info object!");
        return NULL;
    }

    memcpy(fi, &template_LinuxFileInfo, sizeof(template_LinuxFileInfo));
    fi->i_IFileInfo.object = fi;

    fi->mFilename = "<<unknown>>";
    fi->mOperation = operation;
    fi->mFlags = flags;
    fi->mMode = inode->i_mode;
    fi->mIno = inode->i_ino;
    fi->mInode = inode;
    fi->mDevice = kdev_t_to_nr(inode_dev(inode));
    fi->mDeviceMajor = MAJOR(inode_dev(inode));
    fi->mDeviceMinor = MINOR(inode_dev(inode));

    return fi;
}

static void deleteLinuxFileInfo(struct tag_LinuxFileInfo* object)
{
    if ( likely(object != 0) )
    {
        if ( atomic_dec_and_test(&object->mRefCnt) )
        {
            if ( likely(object->mVFSMount != 0) )
            {
                mntput(object->mVFSMount);
            }

            free_page((unsigned long)object->mPage);
            kfree(object->mDeviceName);
            kfree(object->mFSType);
            kfree(object);
        }
    }
    return;
}

/*
* IFileInfo.
*/
static void get(const void* self)
{
    atomic_inc(&this->mRefCnt);
    return;
}

static EFilesystemOperation operation(const void* self)
{
    return this->mOperation;
}

static const char* filename(const void* self)
{
    return this->mFilename;
}

static unsigned int flags(const void* self)
{
    return this->mFlags;
}

static unsigned int mode(const void* self)
{
    return this->mMode;
}

static unsigned long inode(const void* self)
{
    return this->mIno;
}

static bool isWritable(const void* self)
{
    if ( this->mFlags & ( O_WRONLY | O_RDWR | O_APPEND | O_CREAT ) )
    {
        return true;
    }

    return false;
}

static bool isWritableAnywhere(const void* self)
{
    if ( this->mInode && ( atomic_read(&this->mInode->i_writecount) > 1 ) )
    {
        return true;
    }
    else if ( !this->mInode && ( this->mWriteCount > 1 ) )
    {
        return true;
    }

    return false;
}

static uint64_t device(const void* self)
{
    return this->mDevice;
}

static uint32_t deviceMajor(const void* self)
{
    return this->mDeviceMajor;
}

static uint32_t deviceMinor(const void* self)
{
    return this->mDeviceMinor;
}

static const char* deviceName(const void* self)
{
    return this->mDeviceName;
}

static const char* fsType(const void* self)
{
    struct vfsmount* mnt;

    if ( unlikely(this->mFSType != NULL) )
    {
        return this->mFSType;
    }

    mnt = this->mVFSMount;

    if ( likely(mnt != 0) )
    {
        if ( likely((this->mDeviceName == NULL) && (mnt->mnt_devname != NULL)) )
        {
            this->mDeviceName = kmalloc(strlen(mnt->mnt_devname) + 1, GFP_KERNEL);
            if ( likely(this->mDeviceName != NULL) )
            {
                strcpy(this->mDeviceName, mnt->mnt_devname);
            }
        }
        if ( likely(mnt->mnt_sb->s_type->name != NULL) )
        {
            this->mFSType = kmalloc(strlen(mnt->mnt_sb->s_type->name) + 1, GFP_KERNEL);
            if ( likely(this->mFSType != NULL) )
            {
                strcpy(this->mFSType, mnt->mnt_sb->s_type->name);
            }
        }
    }

    return this->mFSType;
}

/*
* End of linux_fileinfo.c
*/

