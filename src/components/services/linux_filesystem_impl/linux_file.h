/*
 * linux_fileinfo.h
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
#ifndef H_LINUXFILE
#define H_LINUXFILE

#include <asm/atomic.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/unistd.h>

#include "common/bool.h"
#include "filesystem/ifile.h"


typedef enum
{
    Dentry = 0,
    Exec,
    Cloned
} EOpenType;

typedef struct tag_LinuxFile
{
    IFile                   i_IFile;
    void                    (*delete)(struct tag_LinuxFile* object);
    atomic_t                mRefCnt;
    EOpenType               mOpenType;
    bool                    mWritable;
    struct file*            mFile;
    loff_t                  mOffset;
} LinuxFile;

/*
 * Object Creators.
 */
extern LinuxFile* newLinuxFile(void);
extern LinuxFile* cloneLinuxFile(struct file* fobject);

#endif

/*
 * End of linux_fileinfo.h
 */

