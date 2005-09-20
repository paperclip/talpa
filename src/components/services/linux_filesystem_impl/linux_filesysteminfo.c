/*
 * linux_filesysteminfo.c
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
#include <linux/stat.h>
#include <asm/uaccess.h>

#include "common/talpa.h"
#include "platforms/linux/glue.h"
#include "linux_filesysteminfo.h"
#include "filesystem/isystemroot.h"
#include "app_ctrl/iportability_app_ctrl.h"



/*
 * Forward declare implementation methods.
 */
static void                  get                (const void* self);
static EFilesystemOperation  operation          (const void* self);
static const char*           deviceName         (const void* self);
static const char*           mountPoint         (const void* self);
static const char*           type               (const void* self);
static uint64_t              device             (const void* self);
static uint32_t              deviceMajor        (const void* self);
static uint32_t              deviceMinor        (const void* self);
static void deleteLinuxFilesystemInfo(struct tag_LinuxFilesystemInfo* object);


/*
 * Template Object.
 */
static LinuxFilesystemInfo template_LinuxFilesystemInfo =
    {
        {
            get,
            operation,
            deviceName,
            mountPoint,
            type,
            device,
            deviceMajor,
            deviceMinor,
            0,
            (void (*)(const void*))deleteLinuxFilesystemInfo
        },
        deleteLinuxFilesystemInfo,
        ATOMIC_INIT(1),
        0,
        0,
        0,
        0,
        0,
        0,
        0
    };
#define this    ((LinuxFilesystemInfo*)self)

/* Makes an absolute path from nameidata, and allocates a string for it */
static char* absolutePath(struct nameidata* nd)
{
    char* page;
    char* absolute = NULL;
    ISystemRoot* root;
    char* apath;


    page = (char *)__get_free_page(GFP_KERNEL);

    if ( !page )
    {
        return NULL;
    }

    root = TALPA_Portability()->systemRoot();
    apath = talpa_d_path(nd->dentry, nd->mnt, root->directoryEntry(root->object), root->mountPoint(root->object), page, PAGE_SIZE);

    if ( apath )
    {
        absolute = kmalloc(strlen(apath) + 1, GFP_KERNEL);
        if ( absolute )
        {
            strcpy(absolute, apath);
        }
    }

    free_page((unsigned long)page);

    return absolute;
}

static char* copyString(const char* string)
{
    char* copy = NULL;

    if ( string )
    {
        int len = strlen(string) + 1;
        copy = kmalloc(len, GFP_KERNEL);
        if ( copy )
        {
            memcpy(copy, string, len);
        }
    }

    return copy;
}

/*
 * Object creation/destruction.
 */
LinuxFilesystemInfo* newLinuxFilesystemInfo(EFilesystemOperation operation, char* dev_name, char* dir_name, char* type)
{
    LinuxFilesystemInfo* object;
    struct nameidata nd;


    object = kmalloc(sizeof(template_LinuxFilesystemInfo), SLAB_KERNEL);
    if ( likely(object != 0) )
    {
        memcpy(object, &template_LinuxFilesystemInfo, sizeof(template_LinuxFilesystemInfo));
        object->i_IFilesystemInfo.object = object;

        object->mOperation = operation;

        /* Two cases, mount and umount. On mount we are receiving all the strings and have very little
           extra work to do. On umount we are receiving just the mount point and will get the other data */

        if ( operation == EFS_Mount )
        {
            object->mType = copyString(type);
            if ( !object->mType )
            {
                goto error;
            }

            if ( !talpa_path_lookup(dev_name, TALPA_LOOKUP, &nd) )
            {
                struct inode *inode = nd.dentry->d_inode;

                object->mDeviceName = absolutePath(&nd);

                if (S_ISBLK(inode->i_mode))
                {
                    object->mDevice = kdev_t_to_nr(inode->i_rdev);
                    object->mDeviceMajor = MAJOR(inode->i_rdev);
                    object->mDeviceMinor = MINOR(inode->i_rdev);
                }

                path_release(&nd);
            }

            if ( !object->mDeviceName )
            {
                object->mDeviceName = copyString(dev_name);
                if ( !object->mDeviceName )
                {
                    goto error;
                }
            }

            if ( !talpa_path_lookup(dir_name, TALPA_LOOKUP, &nd) )
            {
                object->mMountPoint = absolutePath(&nd);

                path_release(&nd);
            }

            if ( !object->mMountPoint )
            {
                object->mMountPoint = copyString(dir_name);
                if ( !object->mMountPoint )
                {
                    goto error;
                }
            }
        }
        else if ( operation == EFS_Umount )
        {
            if ( talpa_path_lookup(dir_name, TALPA_LOOKUP, &nd) )
            {
                goto error;
            }

            if ( nd.dentry != nd.mnt->mnt_root )
            {
                notice("Not a root of a mounted filesystem!");
                goto error2;
            }

            object->mMountPoint = absolutePath(&nd);

            if ( !object->mMountPoint )
            {
                object->mMountPoint = copyString(dir_name);
                if ( !object->mMountPoint )
                {
                    goto error2;
                }
            }
            if ( nd.mnt->mnt_devname )
            {
                if ( nd.mnt->mnt_sb->s_bdev )
                {
                    struct nameidata dnd;

                    if ( !talpa_path_lookup(nd.mnt->mnt_devname, TALPA_LOOKUP, &dnd) )
                    {
                        struct inode *inode = dnd.dentry->d_inode;

                        object->mDeviceName = absolutePath(&dnd);

                        if (S_ISBLK(inode->i_mode))
                        {
                            object->mDevice = kdev_t_to_nr(inode->i_rdev);
                            object->mDeviceMajor = MAJOR(kdev_t_to_nr(inode->i_rdev));
                            object->mDeviceMinor = MINOR(kdev_t_to_nr(inode->i_rdev));
                        }

                        path_release(&dnd);
                    }
                }

                if ( !object->mDeviceName )
                {
                    object->mDeviceName = copyString(nd.mnt->mnt_devname);
                    if ( !object->mDeviceName )
                    {
                        goto error2;
                    }
                }
            }

            if ( nd.mnt->mnt_sb->s_type->name )
            {
                object->mType = copyString(nd.mnt->mnt_sb->s_type->name);
                if ( !object->mType )
                {
                    goto error2;
                }
            }

            if ( !object->mType )
            {
                object->mType = copyString(type);
                if ( !object->mType )
                {
                    goto error2;
                }
            }

            dbg("Device %s resolved from mount point %s - %s", object->mDeviceName, object->mMountPoint, object->mType);

            path_release(&nd);
        }
        else
        {
            err("Calling FilesystemInfo constructor with a wrong operation!");
            goto error;
        }

        dbg("NAME:%s MAJOR:%u MINOR:%u",object->mDeviceName, object->mDeviceMajor, object->mDeviceMinor);
    }

    return object;

    error2:
    path_release(&nd);
    error:
    kfree(object->mDeviceName);
    kfree(object->mMountPoint);
    kfree(object->mType);
    kfree(object);

    return NULL;
}

static void deleteLinuxFilesystemInfo(struct tag_LinuxFilesystemInfo* object)
{
    if ( likely(object != 0) )
    {
        if ( atomic_dec_and_test(&object->mRefCnt) )
        {
            kfree(object->mDeviceName);
            kfree(object->mMountPoint);
            kfree(object->mType);
            kfree(object);
        }
    }
    return;
}

/*
 * IFilesystemInfo.
 */
static void get(const void* self)
{
    atomic_inc(&this->mRefCnt);
    return;
}

static EFilesystemOperation  operation(const void* self)
{
    return this->mOperation;
}

static const char* deviceName(const void* self)
{
    return this->mDeviceName;
}

static const char* mountPoint(const void* self)
{
    return this->mMountPoint;
}

static const char* type(const void* self)
{
    return this->mType;
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

/*
 * End of linux_filesysteminfo.c
 */

