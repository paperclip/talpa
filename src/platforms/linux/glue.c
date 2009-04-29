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
#include <linux/fs.h>
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
static char * __talpa_d_path( struct dentry *dentry, struct vfsmount *vfsmnt,
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
            talpa_vfsmount_lock();
            if (vfsmnt->mnt_parent == vfsmnt) {
                talpa_vfsmount_unlock();
                goto global_root;
            }
            dentry = vfsmnt->mnt_mountpoint;
            vfsmnt = vfsmnt->mnt_parent;
            talpa_vfsmount_unlock();
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

char* talpa__d_path( struct dentry *dentry, struct vfsmount *vfsmnt, struct dentry *root, struct vfsmount *rootmnt, char *buffer, int buflen)
{
    char* path;

    /* Get the function pointer for the real __d_path if we're going to call it. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0) || (defined TALPA_HAS_DPATH)

#   if defined TALPA_DPATH_SLES11
    typedef char *(*d_path_func)(const struct path *, struct path *, char *, int, int);
#   elif defined TALPA_DPATH_SUSE103
    typedef char *(*d_path_func)(struct dentry *, struct vfsmount *, struct dentry *, struct vfsmount *, char *buffer, int buflen, int flags);
#   else
    typedef char *(*d_path_func)(struct dentry *, struct vfsmount *, struct dentry *, struct vfsmount *, char *buffer, int buflen);
#   endif


#   if defined TALPA_HAS_DPATH_ADDR
    d_path_func kernel_d_path = (d_path_func)TALPA_DPATH_ADDR;
#   else
    d_path_func kernel_d_path = &__d_path;
#   endif

#   if defined TALPA_DPATH_SLES11
    struct path pathPath;
    struct path rootPath;
#   endif
#endif

#if defined HOLD_DCACHE_LOCK_WHILE_CALLING_D_PATH
    spin_lock(&dcache_lock);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0) || (defined TALPA_HAS_DPATH)
    /* Calling the real __d_path */
#   if defined TALPA_DPATH_SLES11
    pathPath.dentry = dentry;
    pathPath.mnt = vfsmnt;
    rootPath.dentry = root;
    rootPath.mnt = rootmnt;
    path = kernel_d_path(&pathPath, &rootPath, buffer, buflen, 0);
#   elif defined TALPA_DPATH_SUSE103
    path = kernel_d_path(dentry, vfsmnt, root, rootmnt, buffer, buflen, 0);
#   else
    path = kernel_d_path(dentry, vfsmnt, root, rootmnt, buffer, buflen);
#   endif
#else
    /* Call our own version */
    path = __talpa_d_path(dentry, vfsmnt, root, rootmnt, buffer, buflen);
#endif

#if defined HOLD_DCACHE_LOCK_WHILE_CALLING_D_PATH
    spin_unlock(&dcache_lock);
#endif

    if ( unlikely( IS_ERR(path) != 0 ) )
    {
        path = NULL;
    }

    return path;
}

/*
* End of linux_glue.c
*/

