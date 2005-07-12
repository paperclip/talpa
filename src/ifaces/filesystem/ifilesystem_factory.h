/*
 * ifilesystem_factory.h
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
#ifndef H_IFILESYSTEMFACTORY
#define H_IFILESYSTEMFACTORY

#include "efilesystem_operation.h"
#include "ifile.h"
#include "ifile_info.h"
#include "ifilesystem_info.h"

typedef struct
{
    IFile*                (*newFile)                        (const void* self);
    IFile*                (*cloneFile)                      (const void* self, void* fobject);
    IFileInfo*            (*newFileInfo)                    (const void* self, EFilesystemOperation operation, const char* filename, int flags, int mode);
    IFileInfo*            (*newFileInfoFromFd)              (const void* self, EFilesystemOperation operation, int fd);
    IFileInfo*            (*newFileInfoFromFile)            (const void* self, EFilesystemOperation operation, void* file);
    IFileInfo*            (*newFileInfoFromDirectoryEntry)  (const void* self, EFilesystemOperation operation, void* dentry, void* mnt, int flags, int mode);
    IFileInfo*            (*newFileInfoFromInode)           (const void* self, EFilesystemOperation operation, void* inode, int flags);
    IFilesystemInfo*      (*newFilesystemInfo)              (const void* self, EFilesystemOperation operation, char* dev_name, char* dir_name, char* type);
    /*
     *  Object supporting this interface instance.
     */
    void*   object;
    void    (*delete)(const void* self);
} IFilesystemFactory;

#endif

/*
 * End of ifilesystem_factory.h
 */
