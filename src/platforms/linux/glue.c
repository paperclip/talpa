/*
* linux_glue.c
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

#include <asm/atomic.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/mount.h>
#include <linux/sched.h>

#include "platforms/linux/glue.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0) && (!defined TALPA_HAS_DPATH)
/**
 * d_path - return the path of a dentry
 * @dentry: dentry to report
 * @vfsmnt: vfsmnt to which the dentry belongs
 * @root: root dentry
 * @rootmnt: vfsmnt to which the root dentry belongs
 * @buffer: buffer to return value in
 * @buflen: buffer length
 *
 * Convert a dentry into an ASCII path name. If the entry has been deleted
 * the string " (deleted)" is appended. Note that this is ambiguous.
 *
 * Returns the buffer or an error code if the path was too long.
 *
 * "buflen" should be positive. Caller holds the dcache_lock.
 */
static char * __d_path( struct dentry *dentry, struct vfsmount *vfsmnt,
            struct dentry *root, struct vfsmount *rootmnt,
            char *buffer, int buflen)
{
    char * end = buffer+buflen;
    char * retval;
    int namelen;

    *--end = '\0';
    buflen--;
    if (!IS_ROOT(dentry) && d_unhashed(dentry)) {
        buflen -= 10;
        end -= 10;
        if (buflen < 0)
            goto Elong;
        memcpy(end, " (deleted)", 10);
    }

    if (buflen < 1)
        goto Elong;
    /* Get '/' right */
    retval = end-1;
    *retval = '/';

    for (;;) {
        struct dentry * parent;

        if (dentry == root && vfsmnt == rootmnt)
            break;
        if (dentry == vfsmnt->mnt_root || IS_ROOT(dentry)) {
            /* Global root? */
/* FIXME: We can't grab the lock below here since it is not exported.
   But we must replicate kernels __d_path in order to find out the
   absolute path of a file. So the question is can we get away with
   not taking the lock? Can our parent mount go away while there are
   accesses to files on his child mount? As far as I understand it no,
   so this should be safe. */
/*             spin_lock(&vfsmount_lock); */
            if (vfsmnt->mnt_parent == vfsmnt) {
/*                 spin_unlock(&vfsmount_lock); */
                goto global_root;
            }
            dentry = vfsmnt->mnt_mountpoint;
            vfsmnt = vfsmnt->mnt_parent;
/*             spin_unlock(&vfsmount_lock); */
            continue;
        }
        parent = dentry->d_parent;
        prefetch(parent);
        namelen = dentry->d_name.len;
        buflen -= namelen + 1;
        if (buflen < 0)
            goto Elong;
        end -= namelen;
        memcpy(end, dentry->d_name.name, namelen);
        *--end = '/';
        retval = end;
        dentry = parent;
    }

    return retval;

global_root:
    namelen = dentry->d_name.len;
    buflen -= namelen;
    if (buflen < 0)
        goto Elong;
    retval -= namelen-1;    /* hit the slash */
    memcpy(retval, dentry->d_name.name, namelen);
    return retval;
Elong:
    return ERR_PTR(-ENAMETOOLONG);
}
#endif /* >= 2.6.0 */

char* talpa_d_path( struct dentry *dentry, struct vfsmount *vfsmnt, struct dentry *root, struct vfsmount *rootmnt, char *buffer, int buflen)
{
    char* path;

    spin_lock(&dcache_lock);
    path = __d_path(dentry, vfsmnt, root, rootmnt, buffer, buflen);
    spin_unlock(&dcache_lock);

    return path;
}

/*
* End of linux_glue.c
*/

