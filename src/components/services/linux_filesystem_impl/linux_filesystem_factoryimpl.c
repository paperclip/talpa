/*
 * linux_filesystem_factoryimpl.c
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
#include "linux_filesystem_factoryimpl.h"
#include "linux_file.h"
#include "linux_fileinfo.h"
#include "linux_filesysteminfo.h"

/*
 * Forward declare implementation methods.
 */
static IFile* newFile(const void* self);
static IFile* cloneFile(const void* self, void* fobject);
static IFileInfo* newFileInfo(const void* self, EFilesystemOperation operation, const char* filename, int flags, int mode);
static IFileInfo* newFileInfoFromFd(const void* self, EFilesystemOperation operation, int fd);
static IFileInfo* newFileInfoFromFile(const void* self, EFilesystemOperation operation, void* file);
static IFileInfo* newFileInfoFromDirectoryEntry(const void* self, EFilesystemOperation operation, void* dentry, void* mnt, int flags, int mode);
static IFileInfo* newFileInfoFromInode(const void* self, EFilesystemOperation operation, void* inode, int flags);
static IFilesystemInfo* newFilesystemInfo(const void* self, EFilesystemOperation operation, char* dev_name, char* dir_name, char* type);
static void deleteLinuxFilesystemFactoryImpl(struct tag_LinuxFilesystemFactoryImpl* object);

/*
 * Singleton object.
 */
static LinuxFilesystemFactoryImpl GL_object =
    {
        {
            newFile,
            cloneFile,
            newFileInfo,
            newFileInfoFromFd,
            newFileInfoFromFile,
            newFileInfoFromDirectoryEntry,
            newFileInfoFromInode,
            newFilesystemInfo,
            &GL_object,
            (void (*)(const void*))deleteLinuxFilesystemFactoryImpl
        },
        deleteLinuxFilesystemFactoryImpl,
    };


/*
 * Object creation/destruction.
 */
LinuxFilesystemFactoryImpl* newLinuxFilesystemFactoryImpl(void)
{
    return &GL_object;
}

static void deleteLinuxFilesystemFactoryImpl(struct tag_LinuxFilesystemFactoryImpl* object)
{
    return;
}


/*
 * IFilesystemFactory.
 */
static IFile* newFile(const void* self)
{
    LinuxFile*  object;


    object = newLinuxFile();
    return (object != NULL) ? &object->i_IFile : NULL;
}

static IFile* cloneFile(const void* self, void* fobject)
{
    LinuxFile*  object;


    object = cloneLinuxFile(fobject);
    return (object != NULL) ? &object->i_IFile : NULL;
}

static IFileInfo* newFileInfo(const void* self, EFilesystemOperation operation, const char* filename, int flags, int mode)
{
    LinuxFileInfo*  object;


    object = newLinuxFileInfo(operation, filename, flags, mode);
    return (object != NULL) ? &object->i_IFileInfo : NULL;
}

static IFileInfo* newFileInfoFromFd(const void* self, EFilesystemOperation operation, int fd)
{
    LinuxFileInfo*  object;


    object = newLinuxFileInfoFromFd(operation, fd);
    return (object != NULL) ? &object->i_IFileInfo : NULL;
}

static IFileInfo* newFileInfoFromFile(const void* self, EFilesystemOperation operation, void* file)
{
    LinuxFileInfo*  fi;


    fi = newLinuxFileInfoFromFile(operation, file);
    return (fi != NULL) ? &fi->i_IFileInfo : NULL;
}

static IFileInfo* newFileInfoFromDirectoryEntry(const void* self, EFilesystemOperation operation, void* dentry, void* mnt, int flags, int mode)
{
    LinuxFileInfo*  fi;


    fi = newLinuxFileInfoFromDirectoryEntry(operation, dentry, mnt, flags, mode);
    return (fi != NULL) ? &fi->i_IFileInfo : NULL;
}

static IFileInfo* newFileInfoFromInode(const void* self, EFilesystemOperation operation, void* inode, int flags)
{
    LinuxFileInfo*  fi;


    fi = newLinuxFileInfoFromInode(operation, inode, flags);
    return (fi != NULL) ? &fi->i_IFileInfo : NULL;
}

static IFilesystemInfo* newFilesystemInfo(const void* self, EFilesystemOperation operation, char* dev_name, char* dir_name, char* type)
{
    LinuxFilesystemInfo*  object;


    object = newLinuxFilesystemInfo(operation, dev_name, dir_name, type);
    return (object != NULL) ? &object->i_IFilesystemInfo : NULL;
}

/*
 * End of linux_filesystem_factoryimpl.c
 */
