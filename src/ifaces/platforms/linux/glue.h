/*
 * linux_glue.h
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
#ifndef H_LINUXGLUE
#define H_LINUXGLUE

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/autoconf.h>
#include <linux/module.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <asm/param.h>
#include <linux/types.h>
#include <asm/page.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/kdev_t.h>
#define TALPA_LOOKUP (LOOKUP_FOLLOW)
#define inode_dev(i) ((i)->i_sb->s_dev)
#define kdev_t_to_nr old_encode_dev
#else
#define TALPA_LOOKUP (LOOKUP_FOLLOW|LOOKUP_POSITIVE)
#define inode_dev(i) ((i)->i_dev)
#endif

#ifndef likely
#define likely(x)       __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x)     __builtin_expect(!!(x), 0)
#endif


/* FIXME: This is not really a fixme, but a reminder that
          the avaibility of the constant below must be checked
          in new kernels.
          Last-known-good: 2.6.13 */
#define PF_TALPA_INTERNAL    0x80000000

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)

#define try_module_get(m) \
({ \
    MOD_INC_USE_COUNT; \
    1; \
})

#define module_put(m) \
({ \
    MOD_DEC_USE_COUNT; \
    1; \
})

#endif

#ifndef MODULE_LICENSE
#define MODULE_LICENSE(x) const char module_license[] = x
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0) || defined TALPA_HAS_NEW_PARENT
#define processParentPID(task) task->parent->pid
#else
#define processParentPID(task) task->p_pptr->pid
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,10) && !defined TALPA_HAS_SNPRINTF
#define snprintf(string, len, arg...) sprintf(string, ## arg)
#endif

char * talpa_d_path( struct dentry *dentry, struct vfsmount *vfsmnt,
            struct dentry *root, struct vfsmount *rootmnt,
            char *buffer, int buflen);


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,21)
static inline int talpa_path_lookup(const char *path, unsigned flags, struct nameidata *nd)
{
        int error = 0;
        if (path_init(path, flags, nd))
                error = path_walk(path, nd);
        return error;
}
#else
#define talpa_path_lookup path_lookup
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)

#ifdef _LINUX_HZ_H

/*
 * Thanks to SuSE 'smart' kernel hack we need these to be a run-time calculation
 */

static inline unsigned long msecs_to_jiffies(unsigned long ms)
{
    return ms*HZ/1000;
}

static inline unsigned long jiffies_to_msecs(unsigned long jiffies)
{
    return jiffies*1000/HZ;
}

#else
# if HZ == 1000
#  define jiffies_to_msecs(x)    (x)
#  define msecs_to_jiffies(x)    (x)
# elif HZ == 100
#  define jiffies_to_msecs(x)    ((x) * 10)
#  define msecs_to_jiffies(x)    ((x) / 10)
# else
#  define jiffies_to_msecs(x)    ((x) * 1000 / HZ)
#  define msecs_to_jiffies(x)    ((x) * HZ / 1000)
# endif
#endif

#else /* version >= 2.6.0 */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,7)) && !TALPA_HAS_BACKPORTED_JIFFIES

static inline unsigned long msecs_to_jiffies(const unsigned int m)
{
#if HZ <= 1000 && !(1000 % HZ)
        return (m + (1000 / HZ) - 1) / (1000 / HZ);
#elif HZ > 1000 && !(HZ % 1000)
        return m * (HZ / 1000);
#else
        return (m * HZ + 999) / 1000;
#endif
}

#endif /* version < 2.6.7 */

#endif /* version < 2.6.0 */

#endif

/*
 * End of linux_glue.h
 */

