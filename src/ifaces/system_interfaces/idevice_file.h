/*
 * idevice_file.h
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
#ifndef H_IDEVICEFILE
#define H_IDEVICEFILE

#include <linux/fs.h>

typedef struct
{
    int             (*open) (struct inode* inode, struct file* file);
    int             (*close)(struct inode* inode, struct file* file);
    ssize_t         (*read) (struct file* file, char* buf, size_t len, loff_t* ppos);
    ssize_t         (*write)(struct file* file, const char* buf, size_t len, loff_t* ppos);
    int             (*ioctl)(struct inode* inode, struct file* file, unsigned int cmd, unsigned long arg);
    unsigned int    (*poll) (struct file* file, struct poll_table_struct* polltbl);

    /*
     *  Object supporting this interface instance.
     */
    void* object;
    void  (*delete)               (void* self);
} IDeviceFile;

#endif

/*
 * End of idevice_file.h
 */

