/*
 * talpa_capability.h
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
#ifndef H_TALPACAPABILITY
#define H_TALPACAPABILITY

#include <linux/security.h>



struct talpa_capability_interceptor
{
    int (*inode_permission)(struct inode *inode, int mask, struct nameidata *nd);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
    int (*inode_init_security)(struct inode *inode, struct inode *dir, char **name, void **value, size_t *len);
#else
    void (*inode_post_create)(struct inode *dir, struct dentry *dentry, int mode);
#endif
    int (*bprm_check_security)(struct linux_binprm* bprm);
    void (*file_free_security)(struct file *file);
    int (*sb_mount)(char *dev_name, struct nameidata *nd, char *type, unsigned long flags, void *data);
    int (*sb_umount)(struct vfsmount *mnt, int flags);
};

/*
 * Register yourself if you want talpa_capability to call you.
 * You must define all the hooks because talpa_capability does no checking!
 */
int talpa_capability_register(struct talpa_capability_interceptor* interceptor);

/*
 * Unregister may sleep until the last caller exits.
 */
void talpa_capability_unregister(struct talpa_capability_interceptor* interceptor);

#endif

/*
 * End of talpa_capability.h
 */
