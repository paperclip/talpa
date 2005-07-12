/*
 * talpa_capability.c
 *
 * TALPA Filesystem Interceptor
 *
 * Copyright(C) 2004 Sophos Plc, Oxford, England.
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
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/wait.h>
#include <asm/atomic.h>

#include "platforms/linux/talpa_capability.h"



#ifdef TALPA_ID
const char talpa_id[] = "$TALPA_ID:" TALPA_ID;
#endif

#define err(format, arg...) printk(KERN_ERR "talpa-capability: " format "\n" , ## arg)
#define warn(format, arg...) printk(KERN_WARNING "talpa-capability: " format "\n" , ## arg)
#define notice(format, arg...) printk(KERN_NOTICE "talpa-capability: " format "\n" , ## arg)
#define info(format, arg...) printk(KERN_INFO "talpa-capability: " format "\n" , ## arg)


static atomic_t usecnt = ATOMIC_INIT(0);
static struct talpa_capability_interceptor* interceptor;
static DECLARE_WAIT_QUEUE_HEAD(unregister_wait);


int talpa_capability_register(struct talpa_capability_interceptor* i)
{
    if ( interceptor )
    {
        return -EBUSY;
    }

    if ( !i )
    {
        return -EINVAL;
    }

    atomic_inc(&usecnt);
    interceptor = i;

    return 0;
}

void talpa_capability_unregister(struct talpa_capability_interceptor* i)
{
    if ( (!interceptor) || (!i) || (i != interceptor) )
    {
        return;
    }

    /* Remove interceptor, so that no new callers can get into it */
    interceptor = NULL;
    /* We will now care about wake ups */
    atomic_dec(&usecnt);
    /* Now wait for a last caller to exit */
    wait_event(unregister_wait, atomic_read(&usecnt) == 0);

    return;
}

EXPORT_SYMBOL_GPL(talpa_capability_register);
EXPORT_SYMBOL_GPL(talpa_capability_unregister);

static int talpa_inode_permission(struct inode *inode, int mask, struct nameidata *nd)
{
    struct talpa_capability_interceptor* i;
    int ret = 0;

    atomic_inc(&usecnt);

    i = interceptor;

    if ( likely( i != NULL ) )
    {
        ret = i->inode_permission(inode, mask, nd);
    }

    if ( unlikely( atomic_dec_and_test(&usecnt) != 0 ) )
    {
        wake_up(&unregister_wait);
    }

    return ret;
}

static void talpa_inode_post_create(struct inode *dir, struct dentry *dentry, int mode)
{
    struct talpa_capability_interceptor* i;

    atomic_inc(&usecnt);

    i = interceptor;

    if ( likely( i != NULL ) )
    {
        i->inode_post_create(dir, dentry, mode);
    }

    if ( unlikely( atomic_dec_and_test(&usecnt) != 0 ) )
    {
        wake_up(&unregister_wait);
    }
}

static int talpa_bprm_check_security(struct linux_binprm* bprm)
{
    struct talpa_capability_interceptor* i;
    int ret = 0;

    atomic_inc(&usecnt);

    i = interceptor;

    if ( likely( i != NULL ) )
    {
        ret = i->bprm_check_security(bprm);
    }

    if ( unlikely( atomic_dec_and_test(&usecnt) != 0 ) )
    {
        wake_up(&unregister_wait);
    }

    return ret;
}

static void talpa_file_free_security(struct file *file)
{
    struct talpa_capability_interceptor* i;

    atomic_inc(&usecnt);

    i = interceptor;

    if ( likely( i != NULL ) )
    {
        i->file_free_security(file);
    }

    if ( unlikely( atomic_dec_and_test(&usecnt) != 0 ) )
    {
        wake_up(&unregister_wait);
    }
}

static int talpa_sb_mount(char *dev_name, struct nameidata *nd, char *type, unsigned long flags, void *data)
{
    struct talpa_capability_interceptor* i;
    int ret = 0;

    atomic_inc(&usecnt);

    i = interceptor;

    if ( likely( i != NULL ) )
    {
        ret = i->sb_mount(dev_name, nd, type, flags, data);
    }

    if ( unlikely( atomic_dec_and_test(&usecnt) != 0 ) )
    {
        wake_up(&unregister_wait);
    }

    return ret;
}

static int talpa_sb_umount(struct vfsmount *mnt, int flags)
{
    struct talpa_capability_interceptor* i;
    int ret = 0;

    atomic_inc(&usecnt);

    i = interceptor;

    if ( likely( i != NULL ) )
    {
        ret = i->sb_umount(mnt, flags);
    }

    if ( unlikely( atomic_dec_and_test(&usecnt) != 0 ) )
    {
        wake_up(&unregister_wait);
    }

    return ret;
}



struct security_operations talpa_capability_ops = {
/* Capabilities part */
    .ptrace =                   cap_ptrace,
    .capget =                   cap_capget,
    .capset_check =             cap_capset_check,
    .capset_set =               cap_capset_set,
    .capable =                  cap_capable,
    .netlink_send =             cap_netlink_send,
    .netlink_recv =             cap_netlink_recv,

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,6)) || defined TALPA_HAS_266_LSM
    .bprm_apply_creds =         cap_bprm_apply_creds,
#else
    .bprm_compute_creds =       cap_bprm_compute_creds,
#endif
    .bprm_set_security =        cap_bprm_set_security,
    .bprm_secureexec =          cap_bprm_secureexec,

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,2)
    .inode_setxattr =           cap_inode_setxattr,
    .inode_removexattr =        cap_inode_removexattr,
#endif

    .task_post_setuid =         cap_task_post_setuid,
    .task_reparent_to_init =    cap_task_reparent_to_init,

    .syslog =                   cap_syslog,

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
    .settime =                  cap_settime,
#endif

    .vm_enough_memory =         cap_vm_enough_memory,

/* Talpa part */
    .inode_permission =         talpa_inode_permission,
    .inode_post_create =        talpa_inode_post_create,

    .file_free_security =       talpa_file_free_security,

    .bprm_check_security =      talpa_bprm_check_security,

    .sb_mount =                 talpa_sb_mount,
    .sb_umount =                talpa_sb_umount,
};

static int secondary;

static int __init talpa_capability_init(void)
{
    int ret;

    ret = register_security(&talpa_capability_ops);
    if ( ret )
    {
        ret = mod_reg_security("talpa-capability", &talpa_capability_ops);
        if ( ret )
        {
            err("Failure registering security module!");
            return ret;
        }
        info("Registered as secondary security module");
        secondary = 1;
    }
    else
    {
        info("Registered as primary security module");
    }

    return ret;

}

static void __exit talpa_capability_exit(void)
{
    if ( secondary )
    {
        if ( mod_unreg_security("talpa-capability", &talpa_capability_ops) )
        {
            err("Failure unregistering security module!");
        }
    }
    else
    {
        if ( unregister_security(&talpa_capability_ops) )
        {
            err("Failure unregistering security module!");
        }
    }

    /* Now wait for a last caller to exit */
    wait_event(unregister_wait, atomic_read(&usecnt) == 0);
}

module_init(talpa_capability_init);
module_exit(talpa_capability_exit);

MODULE_DESCRIPTION("Provides Linux Capabilities and allows stacking of talpa-lsm module.");
MODULE_AUTHOR("Sophos Plc");
MODULE_LICENSE("GPL");

/*
 * End of talpa_capability.c
 */

