/*
 * stacker.c
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
#include <linux/slab.h>
#include <linux/list.h>
#include <asm/semaphore.h>
#include <asm/atomic.h>
#include <linux/rcupdate.h>
#include <linux/wait.h>
#include <linux/security.h>



#ifdef TALPA_ID
const char talpa_id[] = "$TALPA_ID:" TALPA_ID;
#endif

#define err(format, arg...) printk(KERN_ERR "stacker: " format "\n" , ## arg)
#define warn(format, arg...) printk(KERN_WARNING "stacker: " format "\n" , ## arg)
#define notice(format, arg...) printk(KERN_NOTICE "stacker: " format "\n" , ## arg)
#define info(format, arg...) printk(KERN_INFO "stacker: " format "\n" , ## arg)

struct stacked_module
{
    struct list_head            head;
    atomic_t                    usecnt;
    wait_queue_head_t           unload;
    char*                       name;
    struct security_operations* ops_ptr;
    struct security_operations  ops;
};

static struct security_operations dummy_ops;

static DECLARE_MUTEX(stacked_sem);
static LIST_HEAD(stacked_modules);
static atomic_t stacked_count = ATOMIC_INIT(0);


#define set_to_null_if_dummy(ops, function)             \
    do {                                \
        if ( ops->function == dummy_ops.function ) {                   \
            ops->function = NULL;        \
            }                       \
    } while (0)

static void stacker_fix_security(struct security_operations *ops)
{
    set_to_null_if_dummy(ops, ptrace);
    set_to_null_if_dummy(ops, capget);
    set_to_null_if_dummy(ops, capset_check);
    set_to_null_if_dummy(ops, capset_set);
    set_to_null_if_dummy(ops, acct);
    set_to_null_if_dummy(ops, capable);
    set_to_null_if_dummy(ops, quotactl);
    set_to_null_if_dummy(ops, quota_on);
    set_to_null_if_dummy(ops, sysctl);
    set_to_null_if_dummy(ops, syslog);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
    set_to_null_if_dummy(ops, settime);
#endif
    set_to_null_if_dummy(ops, vm_enough_memory);
    set_to_null_if_dummy(ops, bprm_alloc_security);
    set_to_null_if_dummy(ops, bprm_free_security);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,6)) || defined TALPA_HAS_266_LSM
    set_to_null_if_dummy(ops, bprm_apply_creds);
#else
    set_to_null_if_dummy(ops, bprm_compute_creds);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
    set_to_null_if_dummy(ops, bprm_post_apply_creds);
#endif
    set_to_null_if_dummy(ops, bprm_set_security);
    set_to_null_if_dummy(ops, bprm_check_security);
    set_to_null_if_dummy(ops, bprm_secureexec);
    set_to_null_if_dummy(ops, sb_alloc_security);
    set_to_null_if_dummy(ops, sb_free_security);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,3)
    set_to_null_if_dummy(ops, sb_copy_data);
#endif
    set_to_null_if_dummy(ops, sb_kern_mount);
    set_to_null_if_dummy(ops, sb_statfs);
    set_to_null_if_dummy(ops, sb_mount);
    set_to_null_if_dummy(ops, sb_check_sb);
    set_to_null_if_dummy(ops, sb_umount);
    set_to_null_if_dummy(ops, sb_umount_close);
    set_to_null_if_dummy(ops, sb_umount_busy);
    set_to_null_if_dummy(ops, sb_post_remount);
    set_to_null_if_dummy(ops, sb_post_mountroot);
    set_to_null_if_dummy(ops, sb_post_addmount);
    set_to_null_if_dummy(ops, sb_pivotroot);
    set_to_null_if_dummy(ops, sb_post_pivotroot);
    set_to_null_if_dummy(ops, inode_alloc_security);
    set_to_null_if_dummy(ops, inode_free_security);
    set_to_null_if_dummy(ops, inode_create);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
    set_to_null_if_dummy(ops, inode_init_security);
#else
    set_to_null_if_dummy(ops, inode_post_create);
    set_to_null_if_dummy(ops, inode_post_link);
    set_to_null_if_dummy(ops, inode_post_symlink);
    set_to_null_if_dummy(ops, inode_post_mkdir);
    set_to_null_if_dummy(ops, inode_post_mknod);
    set_to_null_if_dummy(ops, inode_post_rename);
#endif
    set_to_null_if_dummy(ops, inode_link);
    set_to_null_if_dummy(ops, inode_unlink);
    set_to_null_if_dummy(ops, inode_symlink);
    set_to_null_if_dummy(ops, inode_mkdir);
    set_to_null_if_dummy(ops, inode_rmdir);
    set_to_null_if_dummy(ops, inode_mknod);
    set_to_null_if_dummy(ops, inode_rename);
    set_to_null_if_dummy(ops, inode_readlink);
    set_to_null_if_dummy(ops, inode_follow_link);
    set_to_null_if_dummy(ops, inode_permission);
    set_to_null_if_dummy(ops, inode_setattr);
    set_to_null_if_dummy(ops, inode_getattr);
    set_to_null_if_dummy(ops, inode_delete);
    set_to_null_if_dummy(ops, inode_setxattr);
    set_to_null_if_dummy(ops, inode_post_setxattr);
    set_to_null_if_dummy(ops, inode_getxattr);
    set_to_null_if_dummy(ops, inode_listxattr);
    set_to_null_if_dummy(ops, inode_removexattr);
    set_to_null_if_dummy(ops, inode_getsecurity);
    set_to_null_if_dummy(ops, inode_setsecurity);
    set_to_null_if_dummy(ops, inode_listsecurity);
    set_to_null_if_dummy(ops, file_permission);
    set_to_null_if_dummy(ops, file_alloc_security);
    set_to_null_if_dummy(ops, file_free_security);
    set_to_null_if_dummy(ops, file_ioctl);
    set_to_null_if_dummy(ops, file_mmap);
    set_to_null_if_dummy(ops, file_mprotect);
    set_to_null_if_dummy(ops, file_lock);
    set_to_null_if_dummy(ops, file_fcntl);
    set_to_null_if_dummy(ops, file_set_fowner);
    set_to_null_if_dummy(ops, file_send_sigiotask);
    set_to_null_if_dummy(ops, file_receive);
    set_to_null_if_dummy(ops, task_create);
    set_to_null_if_dummy(ops, task_alloc_security);
    set_to_null_if_dummy(ops, task_free_security);
    set_to_null_if_dummy(ops, task_setuid);
    set_to_null_if_dummy(ops, task_post_setuid);
    set_to_null_if_dummy(ops, task_setgid);
    set_to_null_if_dummy(ops, task_setpgid);
    set_to_null_if_dummy(ops, task_getpgid);
    set_to_null_if_dummy(ops, task_getsid);
    set_to_null_if_dummy(ops, task_setgroups);
    set_to_null_if_dummy(ops, task_setnice);
    set_to_null_if_dummy(ops, task_setrlimit);
    set_to_null_if_dummy(ops, task_setscheduler);
    set_to_null_if_dummy(ops, task_getscheduler);
    set_to_null_if_dummy(ops, task_wait);
    set_to_null_if_dummy(ops, task_kill);
    set_to_null_if_dummy(ops, task_prctl);
    set_to_null_if_dummy(ops, task_reparent_to_init);
    set_to_null_if_dummy(ops, task_to_inode);
    set_to_null_if_dummy(ops, ipc_permission);
    set_to_null_if_dummy(ops, msg_msg_alloc_security);
    set_to_null_if_dummy(ops, msg_msg_free_security);
    set_to_null_if_dummy(ops, msg_queue_alloc_security);
    set_to_null_if_dummy(ops, msg_queue_free_security);
    set_to_null_if_dummy(ops, msg_queue_associate);
    set_to_null_if_dummy(ops, msg_queue_msgctl);
    set_to_null_if_dummy(ops, msg_queue_msgsnd);
    set_to_null_if_dummy(ops, msg_queue_msgrcv);
    set_to_null_if_dummy(ops, shm_alloc_security);
    set_to_null_if_dummy(ops, shm_free_security);
    set_to_null_if_dummy(ops, shm_associate);
    set_to_null_if_dummy(ops, shm_shmctl);
    set_to_null_if_dummy(ops, shm_shmat);
    set_to_null_if_dummy(ops, sem_alloc_security);
    set_to_null_if_dummy(ops, sem_free_security);
    set_to_null_if_dummy(ops, sem_associate);
    set_to_null_if_dummy(ops, sem_semctl);
    set_to_null_if_dummy(ops, sem_semop);
    set_to_null_if_dummy(ops, netlink_send);
    set_to_null_if_dummy(ops, netlink_recv);
    set_to_null_if_dummy(ops, register_security);
    set_to_null_if_dummy(ops, unregister_security);
    set_to_null_if_dummy(ops, d_instantiate);
    set_to_null_if_dummy(ops, getprocattr);
    set_to_null_if_dummy(ops, setprocattr);
#ifdef CONFIG_SECURITY_NETWORK
    set_to_null_if_dummy(ops, unix_stream_connect);
    set_to_null_if_dummy(ops, unix_may_send);
    set_to_null_if_dummy(ops, socket_create);
    set_to_null_if_dummy(ops, socket_post_create);
    set_to_null_if_dummy(ops, socket_bind);
    set_to_null_if_dummy(ops, socket_connect);
    set_to_null_if_dummy(ops, socket_listen);
    set_to_null_if_dummy(ops, socket_accept);
    set_to_null_if_dummy(ops, socket_post_accept);
    set_to_null_if_dummy(ops, socket_sendmsg);
    set_to_null_if_dummy(ops, socket_recvmsg);
    set_to_null_if_dummy(ops, socket_getsockname);
    set_to_null_if_dummy(ops, socket_getpeername);
    set_to_null_if_dummy(ops, socket_setsockopt);
    set_to_null_if_dummy(ops, socket_getsockopt);
    set_to_null_if_dummy(ops, socket_shutdown);
    set_to_null_if_dummy(ops, socket_sock_rcv_skb);
  #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,2)
    set_to_null_if_dummy(ops, socket_getpeersec);
    set_to_null_if_dummy(ops, sk_alloc_security);
    set_to_null_if_dummy(ops, sk_free_security);
  #endif
  #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
    set_to_null_if_dummy(ops, sk_getsid);
  #endif
#endif  /* CONFIG_SECURITY_NETWORK */
#ifdef CONFIG_SECURITY_NETWORK_XFRM
    set_to_null_if_dummy(ops, xfrm_policy_alloc_security);
    set_to_null_if_dummy(ops, xfrm_policy_clone_security);
    set_to_null_if_dummy(ops, xfrm_policy_free_security);
    set_to_null_if_dummy(ops, xfrm_state_alloc_security);
    set_to_null_if_dummy(ops, xfrm_state_free_security);
    set_to_null_if_dummy(ops, xfrm_policy_lookup);
#endif  /* CONFIG_SECURITY_NETWORK_XFRM */
#ifdef CONFIG_KEYS
    set_to_null_if_dummy(ops, key_alloc);
    set_to_null_if_dummy(ops, key_free);
    set_to_null_if_dummy(ops, key_permission);
#endif /* CONFIG_KEYS */
}

static int stacker_register_security(const char *name, struct security_operations *ops)
{
    struct stacked_module* sm;
    unsigned int nlen;

    if ( !name || !ops )
    {
        return -EINVAL;
    }

    if ( !try_module_get(THIS_MODULE) )
    {
        return -EBUSY;
    }

    sm = kmalloc(sizeof(struct stacked_module), GFP_KERNEL);

    if ( !sm )
    {
        module_put(THIS_MODULE);
        return -ENOMEM;
    }

    nlen = strlen(name) + 1;
    sm->name = kmalloc(nlen, GFP_KERNEL);

    if ( !sm->name )
    {
        kfree(sm);
        module_put(THIS_MODULE);
        return -ENOMEM;
    }

    INIT_LIST_HEAD(&sm->head);
    atomic_set(&sm->usecnt, 1);
    init_waitqueue_head(&sm->unload);
    memcpy(sm->name, name, nlen);
    sm->ops_ptr = ops;
    memcpy(&sm->ops, ops, sizeof(struct security_operations));
    stacker_fix_security(&sm->ops);

    down(&stacked_sem);
    list_add_tail_rcu(&sm->head, &stacked_modules);
    up(&stacked_sem);
    atomic_inc(&stacked_count);

    info("%s added to the chain", name);

    return 0;
}

static int stacker_unregister_security(const char *name, struct security_operations *ops)
{
    struct stacked_module*  sm;
    int err = -ESRCH;


    down(&stacked_sem);
    list_for_each_entry_rcu(sm, &stacked_modules, head)
    {
        if ( ops == sm->ops_ptr )
        {
            break;
        }
    }

    if ( sm )
    {
        /* Remove the module from the list */
        atomic_dec(&stacked_count);
        list_del_rcu(&sm->head);
        up(&stacked_sem);
        atomic_dec(&sm->usecnt);
        info("%s removed from the chain", sm->name);

        /* Now we must wait for users to stop using it */
        wait_event(sm->unload, atomic_read(&sm->usecnt) == 0);

        /* Free the stacked module */
        err = 0;
        kfree(sm->name);
        kfree(sm);
        module_put(THIS_MODULE);
    }
    else
    {
        up(&stacked_sem);
    }

    return err;
}

#define _ALL_STACKED(func, params) \
({ \
    int hooks = 0; \
    struct stacked_module* sm; \
\
    rcu_read_lock(); \
    list_for_each_entry_rcu(sm, &stacked_modules, head) \
    { \
        atomic_inc(&sm->usecnt); \
        rcu_read_unlock(); \
        if ( sm->ops.func ) \
        { \
            sm->ops.func params; \
            hooks++; \
        } \
        rcu_read_lock(); \
        if ( unlikely( atomic_dec_and_test(&sm->usecnt) != 0 ) ) \
        { \
            wake_up(&sm->unload); \
        } \
    } \
    rcu_read_unlock(); \
\
    hooks; \
})

#define ALL_STACKED(func, params) \
do \
{ \
    int ret = 0; \
\
    if ( likely( atomic_read(&stacked_count) > 0 ) ) \
    { \
        ret = _ALL_STACKED(func, params); \
    } \
 \
    if ( unlikely( ret == 0 ) ) \
    { \
        dummy_ops.func params; \
    } \
} while(0)

#define _RESTRICTIVE_STACKED(func, params) \
({ \
    struct stacked_module* sm; \
    int hooks = 0; \
    int result = 0; \
    int ret; \
\
    rcu_read_lock(); \
    list_for_each_entry_rcu(sm, &stacked_modules, head) \
    { \
        atomic_inc(&sm->usecnt); \
        rcu_read_unlock(); \
        if ( sm->ops.func ) \
        { \
            ret = sm->ops.func params; \
            hooks++; \
            if ( unlikely( ret && !result ) ) \
            { \
                result = ret; \
            } \
        } \
        rcu_read_lock(); \
        if ( unlikely( atomic_dec_and_test(&sm->usecnt) != 0 ) ) \
        { \
            wake_up(&sm->unload); \
        } \
    } \
    rcu_read_unlock(); \
\
    if ( unlikely( hooks == 0 ) ) \
    { \
        result = dummy_ops.func params; \
    } \
\
    result; \
})

#define RESTRICTIVE_STACKED(func, params) \
({ \
    int ret; \
\
    if ( likely( atomic_read(&stacked_count) > 0 ) ) \
    { \
        ret = _RESTRICTIVE_STACKED(func, params); \
    } \
    else \
    { \
        ret = dummy_ops.func params; \
    } \
\
    ret; \
})

#define _ALLOC_STACKED(alloc_func, alloc_params, free_func, free_params) \
({ \
    struct stacked_module *sm, *sm2; \
    int hooks = 0; \
    int ret = 0; \
\
    rcu_read_lock(); \
    list_for_each_entry_rcu(sm, &stacked_modules, head) \
    { \
        atomic_inc(&sm->usecnt); \
        rcu_read_unlock(); \
        if ( sm->ops.alloc_func ) \
        { \
            ret = sm->ops.alloc_func alloc_params; \
            hooks++; \
        } \
        rcu_read_lock(); \
        if ( unlikely( atomic_dec_and_test(&sm->usecnt) != 0 ) ) \
        { \
            wake_up(&sm->unload); \
        } \
        if ( unlikely( ret != 0 ) ) \
        { \
            break; \
        } \
    } \
    if ( unlikely( sm && ret ) ) \
    { \
        list_for_each_entry_rcu(sm2, &stacked_modules, head) \
        { \
            if ( sm2 == sm ) \
            { \
                break; \
            } \
            atomic_inc(&sm2->usecnt); \
            rcu_read_unlock(); \
            if ( sm2->ops.free_func ) \
            { \
                sm2->ops.free_func free_params; \
            } \
            rcu_read_lock(); \
            if ( unlikely( atomic_dec_and_test(&sm2->usecnt) != 0 ) ) \
            { \
                wake_up(&sm2->unload); \
            } \
        } \
    } \
    rcu_read_unlock(); \
\
    ret; \
})

#define ALLOC_STACKED(alloc_func, alloc_params, free_func, free_params) \
({ \
    int ret; \
\
    if ( likely( atomic_read(&stacked_count) > 0 ) ) \
    { \
        ret = _ALLOC_STACKED(alloc_func, alloc_params, free_func, free_params); \
    } \
    else \
    { \
        ret = dummy_ops.alloc_func alloc_params; \
    } \
\
    ret; \
})

#define _AUTHORITATIVE_STACKED(func, params) \
({ \
    struct stacked_module* sm; \
    int hooks = 0; \
    int result = 0; \
    int ret; \
\
    rcu_read_lock(); \
    list_for_each_entry_rcu(sm, &stacked_modules, head) \
    { \
        atomic_inc(&sm->usecnt); \
        rcu_read_unlock(); \
        if ( sm->ops.func ) \
        { \
            ret = sm->ops.func params; \
            hooks++; \
            if ( unlikely( ret && !result ) ) \
            { \
                result = ret; \
            } \
        } \
        rcu_read_lock(); \
        if ( unlikely( atomic_dec_and_test(&sm->usecnt) != 0 ) ) \
        { \
            wake_up(&sm->unload); \
        } \
    } \
    rcu_read_unlock(); \
\
    if ( unlikely( hooks == 0 ) ) \
    { \
        result = dummy_ops.func params; \
    } \
\
    result; \
})

#define AUTHORITATIVE_STACKED(func, params) \
({ \
    int ret; \
\
    if ( likely( atomic_read(&stacked_count) > 0 ) ) \
    { \
        ret = _AUTHORITATIVE_STACKED(func, params); \
    } \
    else \
    { \
        ret = dummy_ops.func params; \
    } \
\
    ret; \
})

#define _RETURN_ONE_STACKED(func, type, params) \
({ \
    struct stacked_module* sm; \
    int hooks = 0; \
    type result = 0; \
    type ret; \
\
    rcu_read_lock(); \
    list_for_each_entry_rcu(sm, &stacked_modules, head) \
    { \
        atomic_inc(&sm->usecnt); \
        rcu_read_unlock(); \
        if ( sm->ops.func ) \
        { \
            ret = sm->ops.func params; \
            hooks++; \
            if ( unlikely( ret && !result ) ) \
            { \
                result = ret; \
            } \
        } \
        rcu_read_lock(); \
        if ( unlikely( atomic_dec_and_test(&sm->usecnt) != 0 ) ) \
        { \
            wake_up(&sm->unload); \
        } \
    } \
    rcu_read_unlock(); \
\
    if ( unlikely( hooks == 0 ) ) \
    { \
        result = dummy_ops.func params; \
    } \
\
    result; \
})

#define RETURN_ONE_STACKED(func, type, params) \
({ \
    type ret; \
\
    if ( likely( atomic_read(&stacked_count) > 0 ) ) \
    { \
        ret = _RETURN_ONE_STACKED(func, type, params); \
    } \
    else \
    { \
        ret = dummy_ops.func params; \
    } \
\
    ret; \
})

static int stacker_ptrace(struct task_struct * parent, struct task_struct * child)
{
    return RESTRICTIVE_STACKED(ptrace, (parent, child));
}

static int stacker_capget(struct task_struct * target, kernel_cap_t * effective, kernel_cap_t * inheritable, kernel_cap_t * permitted)
{
    return RESTRICTIVE_STACKED(capget, (target, effective, inheritable, permitted));
}

static int stacker_capset_check(struct task_struct * target, kernel_cap_t * effective, kernel_cap_t * inheritable, kernel_cap_t * permitted)
{
    return RESTRICTIVE_STACKED(capset_check, (target, effective, inheritable, permitted));
}

static void stacker_capset_set(struct task_struct * target, kernel_cap_t * effective, kernel_cap_t * inheritable, kernel_cap_t * permitted)
{
    ALL_STACKED(capset_set, (target, effective, inheritable, permitted));
}

static int stacker_acct(struct file * file)
{
    return RESTRICTIVE_STACKED(acct, (file));
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
static int stacker_sysctl(struct ctl_table * table, int op)
{
    return RESTRICTIVE_STACKED(sysctl, (table, op));
}
#else
static int stacker_sysctl(ctl_table * table, int op)
{
    return RESTRICTIVE_STACKED(sysctl, (table, op));
}
#endif

static int stacker_capable(struct task_struct * tsk, int cap)
{
    return AUTHORITATIVE_STACKED(capable, (tsk, cap));
}

static int stacker_quotactl(int cmds, int type, int id, struct super_block * sb)
{
    return RESTRICTIVE_STACKED(quotactl, (cmds, type, id, sb));
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
static int stacker_quota_on(struct dentry * dentry)
{
    return RESTRICTIVE_STACKED(quota_on, (dentry));
}
#else
static int stacker_quota_on(struct file * f)
{
    return RESTRICTIVE_STACKED(quota_on, (f));
}
#endif

static int stacker_syslog(int type)
{
    return RESTRICTIVE_STACKED(syslog, (type));
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
static int stacker_settime(struct timespec *ts, struct timezone *tz)
{
    return RESTRICTIVE_STACKED(settime, (ts, tz));
}
#endif

static int stacker_vm_enough_memory(long pages)
{
    return RESTRICTIVE_STACKED(vm_enough_memory, (pages));
}

static int stacker_bprm_alloc_security(struct linux_binprm * bprm)
{
    return ALLOC_STACKED(bprm_alloc_security, (bprm), bprm_free_security, (bprm));
}

static void stacker_bprm_free_security(struct linux_binprm * bprm)
{
    ALL_STACKED(bprm_free_security, (bprm));
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,6)) || defined TALPA_HAS_266_LSM
static void stacker_bprm_apply_creds(struct linux_binprm * bprm, int unsafe)
{
    ALL_STACKED(bprm_apply_creds, (bprm, unsafe));
}
#else
static void stacker_bprm_compute_creds(struct linux_binprm * bprm)
{
    ALL_STACKED(bprm_compute_creds, (bprm));
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
static void stacker_bprm_post_apply_creds(struct linux_binprm * bprm)
{
    ALL_STACKED(bprm_post_apply_creds, (bprm));
}
#endif

static int stacker_bprm_set_security(struct linux_binprm * bprm)
{
    return RESTRICTIVE_STACKED(bprm_set_security, (bprm));
}

static int stacker_bprm_check_security(struct linux_binprm * bprm)
{
    return RESTRICTIVE_STACKED(bprm_check_security, (bprm));
}

static int stacker_bprm_secureexec(struct linux_binprm * bprm)
{
    return RESTRICTIVE_STACKED(bprm_secureexec, (bprm));
}

static int stacker_sb_alloc_security(struct super_block * sb)
{
    return ALLOC_STACKED(sb_alloc_security, (sb), sb_free_security, (sb));
}

static void stacker_sb_free_security(struct super_block * sb)
{
    ALL_STACKED(sb_free_security, (sb));
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,5)) || defined TALPA_HAS_265_LSM
static int stacker_sb_copy_data(struct file_system_type *type, void *orig, void *copy)
{
    return RESTRICTIVE_STACKED(sb_copy_data, (type, orig, copy));
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,3)
static int stacker_sb_copy_data(const char *fstype, void *orig, void *copy)
{
    return RESTRICTIVE_STACKED(sb_copy_data, (fstype, orig, copy));
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,3)
static int stacker_sb_kern_mount(struct super_block *sb, void *data)
{
    return RESTRICTIVE_STACKED(sb_kern_mount, (sb, data));
}
#else
static int stacker_sb_kern_mount(struct super_block *sb)
{
    return RESTRICTIVE_STACKED(sb_kern_mount, (sb));
}
#endif

static int stacker_sb_statfs(struct super_block * sb)
{
    return RESTRICTIVE_STACKED(sb_statfs, (sb));
}

static int stacker_sb_mount(char *dev_name, struct nameidata * nd, char *type, unsigned long flags, void *data)
{
    return RESTRICTIVE_STACKED(sb_mount, (dev_name, nd, type, flags, data));
}

static int stacker_sb_check_sb(struct vfsmount * mnt, struct nameidata * nd)
{
    return RESTRICTIVE_STACKED(sb_check_sb, (mnt, nd));
}

static int stacker_sb_umount(struct vfsmount * mnt, int flags)
{
    return RESTRICTIVE_STACKED(sb_umount, (mnt, flags));
}

static void stacker_sb_umount_close(struct vfsmount * mnt)
{
    ALL_STACKED(sb_umount_close, (mnt));
}

static void stacker_sb_umount_busy(struct vfsmount * mnt)
{
    ALL_STACKED(sb_umount_busy, (mnt));
}

static void stacker_sb_post_remount(struct vfsmount * mnt, unsigned long flags, void *data)
{
    ALL_STACKED(sb_post_remount, (mnt, flags, data));
}

static void stacker_sb_post_mountroot(void)
{
    ALL_STACKED(sb_post_mountroot, ());
}

static void stacker_sb_post_addmount(struct vfsmount * mnt, struct nameidata * mountpoint_nd)
{
    ALL_STACKED(sb_post_addmount, (mnt, mountpoint_nd));
}

static int stacker_sb_pivotroot(struct nameidata * old_nd, struct nameidata * new_nd)
{
    return RESTRICTIVE_STACKED(sb_pivotroot, (old_nd, new_nd));
}

static void stacker_sb_post_pivotroot(struct nameidata * old_nd, struct nameidata * new_nd)
{
    ALL_STACKED(sb_post_pivotroot, (old_nd, new_nd));
}

static int stacker_inode_alloc_security(struct inode *inode)
{
    return ALLOC_STACKED(inode_alloc_security, (inode), inode_free_security, (inode));
}

static void stacker_inode_free_security(struct inode *inode)
{
    ALL_STACKED(inode_free_security, (inode));
}

static int stacker_inode_create(struct inode *dir, struct dentry *dentry, int mode)
{
    return RESTRICTIVE_STACKED(inode_create, (dir, dentry, mode));
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
static int stacker_inode_init_security(struct inode *inode, struct inode *dir, char **name, void **value, size_t *len)
{
    return AUTHORITATIVE_STACKED(inode_init_security, (inode, dir, name, value, len));
}
#else
static void stacker_inode_post_create(struct inode *dir, struct dentry *dentry, int mode)
{
    ALL_STACKED(inode_post_create, (dir, dentry, mode));
}

static void stacker_inode_post_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
    ALL_STACKED(inode_post_link, (old_dentry, dir, new_dentry));
}

static void stacker_inode_post_symlink(struct inode *dir, struct dentry *dentry, const char *old_name)
{
    ALL_STACKED(inode_post_symlink, (dir, dentry, old_name));
}

static void stacker_inode_post_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
    ALL_STACKED(inode_post_mkdir, (dir, dentry, mode));
}

static void stacker_inode_post_mknod(struct inode *dir, struct dentry *dentry, int mode, dev_t dev)
{
    ALL_STACKED(inode_post_mknod, (dir, dentry, mode, dev));
}

static void stacker_inode_post_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry)
{
    ALL_STACKED(inode_post_rename, (old_dir, old_dentry, new_dir, new_dentry));
}
#endif

static int stacker_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
    return RESTRICTIVE_STACKED(inode_link, (old_dentry, dir, new_dentry));
}

static int stacker_inode_unlink(struct inode *dir, struct dentry *dentry)
{
    return RESTRICTIVE_STACKED(inode_unlink, (dir, dentry));
}

static int stacker_inode_symlink(struct inode *dir, struct dentry *dentry, const char *old_name)
{
    return RESTRICTIVE_STACKED(inode_symlink, (dir, dentry, old_name));
}

static int stacker_inode_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
    return RESTRICTIVE_STACKED(inode_mkdir, (dir, dentry, mode));
}

static int stacker_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
    return RESTRICTIVE_STACKED(inode_rmdir, (dir, dentry));
}

static int stacker_inode_mknod(struct inode *dir, struct dentry *dentry, int mode, dev_t dev)
{
    return RESTRICTIVE_STACKED(inode_mknod, (dir, dentry, mode, dev));
}

static int stacker_inode_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry)
{
    return RESTRICTIVE_STACKED(inode_rename, (old_dir, old_dentry, new_dir, new_dentry));
}

static int stacker_inode_readlink(struct dentry *dentry)
{
    return RESTRICTIVE_STACKED(inode_readlink, (dentry));
}

static int stacker_inode_follow_link(struct dentry *dentry, struct nameidata *nd)
{
    return RESTRICTIVE_STACKED(inode_follow_link, (dentry, nd));
}

static int stacker_inode_permission(struct inode *inode, int mask, struct nameidata *nd)
{
    return RESTRICTIVE_STACKED(inode_permission, (inode, mask, nd));
}

static int stacker_inode_setattr(struct dentry *dentry, struct iattr *attr)
{
    return RESTRICTIVE_STACKED(inode_setattr, (dentry, attr));
}

static int stacker_inode_getattr(struct vfsmount *mnt, struct dentry *dentry)
{
    return RESTRICTIVE_STACKED(inode_getattr, (mnt, dentry));
}

static void stacker_inode_delete(struct inode *inode)
{
    ALL_STACKED(inode_delete, (inode));
}

static int stacker_inode_setxattr(struct dentry *dentry, char *name, void *value, size_t size, int flags)
{
    return RESTRICTIVE_STACKED(inode_setxattr, (dentry, name, value, size, flags));
}

static void stacker_inode_post_setxattr(struct dentry *dentry, char *name, void *value, size_t size, int flags)
{
    ALL_STACKED(inode_post_setxattr, (dentry, name, value, size, flags));
}

static int stacker_inode_getxattr(struct dentry *dentry, char *name)
{
    return RESTRICTIVE_STACKED(inode_getxattr, (dentry, name));
}

static int stacker_inode_listxattr(struct dentry *dentry)
{
    return RESTRICTIVE_STACKED(inode_listxattr, (dentry));
}

static int stacker_inode_removexattr(struct dentry *dentry, char *name)
{
    return RESTRICTIVE_STACKED(inode_removexattr, (dentry, name));
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)) || defined TALPA_HAS_2610_LSM

  #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,15)
static int stacker_inode_getsecurity(struct inode *inode, const char *name, void *buffer, size_t size, int err)
{
    return RESTRICTIVE_STACKED(inode_getsecurity, (inode, name, buffer, size, err));
}
  #else
static int stacker_inode_getsecurity(struct inode *inode, const char *name, void *buffer, size_t size)
{
    return RESTRICTIVE_STACKED(inode_getsecurity, (inode, name, buffer, size));
}
  #endif

static int stacker_inode_setsecurity(struct inode *inode, const char *name, const void *value, size_t size, int flags)
{
    return RESTRICTIVE_STACKED(inode_setsecurity, (inode, name, value, size, flags));
}

static int stacker_inode_listsecurity(struct inode *inode, char *buffer, size_t buffer_size)
{
    return RESTRICTIVE_STACKED(inode_listsecurity, (inode, buffer, buffer_size));
}
#else
static int stacker_inode_getsecurity(struct dentry *dentry, const char *name, void *buffer, size_t size)
{
    return RESTRICTIVE_STACKED(inode_getsecurity, (dentry, name, buffer, size));
}

static int stacker_inode_setsecurity(struct dentry *dentry, const char *name, const void *value, size_t size, int flags)
{
    return RESTRICTIVE_STACKED(inode_setsecurity, (dentry, name, value, size, flags));
}

static int stacker_inode_listsecurity(struct dentry *dentry, char *buffer)
{
    return RESTRICTIVE_STACKED(inode_listsecurity, (dentry, buffer));
}
#endif

static int stacker_file_permission(struct file * file, int mask)
{
    return RESTRICTIVE_STACKED(file_permission, (file, mask));
}

static int stacker_file_alloc_security(struct file * file)
{
    return ALLOC_STACKED(file_alloc_security, (file), file_free_security, (file));
}

static void stacker_file_free_security(struct file * file)
{
    ALL_STACKED(file_free_security, (file));
}

static int stacker_file_ioctl(struct file * file, unsigned int cmd, unsigned long arg)
{
    return RESTRICTIVE_STACKED(file_ioctl, (file, cmd, arg));
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,12)
static int stacker_file_mmap(struct file * file, unsigned long reqprot, unsigned long prot, unsigned long flags)
{
    return RESTRICTIVE_STACKED(file_mmap, (file, reqprot, prot, flags));
}

static int stacker_file_mprotect(struct vm_area_struct * vma, unsigned long reqprot, unsigned long prot)
{
    return RESTRICTIVE_STACKED(file_mprotect, (vma, reqprot, prot));
}
#else
static int stacker_file_mmap(struct file * file, unsigned long prot, unsigned long flags)
{
    return RESTRICTIVE_STACKED(file_mmap, (file, prot, flags));
}

static int stacker_file_mprotect(struct vm_area_struct * vma, unsigned long prot)
{
    return RESTRICTIVE_STACKED(file_mprotect, (vma, prot));
}
#endif

static int stacker_file_lock(struct file * file, unsigned int cmd)
{
    return RESTRICTIVE_STACKED(file_lock, (file, cmd));
}

static int stacker_file_fcntl(struct file * file, unsigned int cmd, unsigned long arg)
{
    return RESTRICTIVE_STACKED(file_fcntl, (file, cmd, arg));
}

static int stacker_file_set_fowner(struct file * file)
{
    return RESTRICTIVE_STACKED(file_set_fowner, (file));
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)) || defined TALPA_HAS_2610_LSM
static int stacker_file_send_sigiotask(struct task_struct * tsk, struct fown_struct * fown, int sig)
{
    return RESTRICTIVE_STACKED(file_send_sigiotask, (tsk, fown, sig));
}
#else
static int stacker_file_send_sigiotask(struct task_struct * tsk, struct fown_struct * fown, int fd, int reason)
{
    return RESTRICTIVE_STACKED(file_send_sigiotask, (tsk, fown, fd, reason));
}
#endif

static int stacker_file_receive(struct file * file)
{
    return RESTRICTIVE_STACKED(file_receive, (file));
}

static int stacker_task_create(unsigned long clone_flags)
{
    return RESTRICTIVE_STACKED(task_create, (clone_flags));
}

static int stacker_task_alloc_security(struct task_struct * p)
{
    return ALLOC_STACKED(task_alloc_security, (p), task_free_security, (p));
}

static void stacker_task_free_security(struct task_struct * p)
{
    ALL_STACKED(task_free_security, (p));
}

static int stacker_task_setuid(uid_t id0, uid_t id1, uid_t id2, int flags)
{
    return RESTRICTIVE_STACKED(task_setuid, (id0, id1, id2, flags));
}

static int stacker_task_post_setuid(uid_t old_ruid /* or fsuid */ , uid_t old_euid, uid_t old_suid, int flags)
{
    return RESTRICTIVE_STACKED(task_post_setuid, (old_ruid, old_euid, old_suid, flags));
}

static int stacker_task_setgid(gid_t id0, gid_t id1, gid_t id2, int flags)
{
    return RESTRICTIVE_STACKED(task_setgid, (id0, id1, id2, flags));
}

static int stacker_task_setpgid(struct task_struct * p, pid_t pgid)
{
    return RESTRICTIVE_STACKED(task_setpgid, (p, pgid));
}

static int stacker_task_getpgid(struct task_struct * p)
{
    return RESTRICTIVE_STACKED(task_getpgid, (p));
}

static int stacker_task_getsid(struct task_struct * p)
{
    return RESTRICTIVE_STACKED(task_getsid, (p));
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,4)
static int stacker_task_setgroups(struct group_info *group_info)
{
    return RESTRICTIVE_STACKED(task_setgroups, (group_info));
}
#else
static int stacker_task_setgroups(int gidsetsize, gid_t *grouplist)
{
    return RESTRICTIVE_STACKED(task_setgroups, (gidsetsize, grouplist));
}
#endif

static int stacker_task_setnice(struct task_struct * p, int nice)
{
    return RESTRICTIVE_STACKED(task_setnice, (p, nice));
}

static int stacker_task_setrlimit(unsigned int resource, struct rlimit * new_rlim)
{
    return RESTRICTIVE_STACKED(task_setrlimit, (resource, new_rlim));
}

static int stacker_task_setscheduler(struct task_struct * p, int policy, struct sched_param * lp)
{
    return RESTRICTIVE_STACKED(task_setscheduler, (p, policy, lp));
}

static int stacker_task_getscheduler(struct task_struct * p)
{
    return RESTRICTIVE_STACKED(task_getscheduler, (p));
}

static int stacker_task_kill(struct task_struct * p, struct siginfo * info, int sig)
{
    return RESTRICTIVE_STACKED(task_kill, (p, info, sig));
}

static int stacker_task_wait(struct task_struct * p)
{
    return RESTRICTIVE_STACKED(task_wait, (p));
}

static int stacker_task_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
    return RESTRICTIVE_STACKED(task_prctl, (option, arg2, arg3, arg4, arg5));
}

static void stacker_task_reparent_to_init(struct task_struct * p)
{
    ALL_STACKED(task_reparent_to_init, (p));
}

static void stacker_task_to_inode(struct task_struct *p, struct inode *inode)
{
    ALL_STACKED(task_to_inode, (p, inode));
}

static int stacker_ipc_permission(struct kern_ipc_perm * ipcp, short flag)
{
    return RESTRICTIVE_STACKED(ipc_permission, (ipcp, flag));
}

static int stacker_msg_msg_alloc_security(struct msg_msg * msg)
{
    return ALLOC_STACKED(msg_msg_alloc_security, (msg), msg_msg_free_security, (msg));
}

static void stacker_msg_msg_free_security(struct msg_msg * msg)
{
    ALL_STACKED(msg_msg_free_security, (msg));
}

static int stacker_msg_queue_alloc_security(struct msg_queue * msq)
{
    return ALLOC_STACKED(msg_queue_alloc_security, (msq), msg_queue_free_security, (msq));
}

static void stacker_msg_queue_free_security(struct msg_queue * msq)
{
    ALL_STACKED(msg_queue_free_security, (msq));
}

static int stacker_msg_queue_associate(struct msg_queue * msq, int msqflg)
{
    return RESTRICTIVE_STACKED(msg_queue_associate, (msq, msqflg));
}

static int stacker_msg_queue_msgctl(struct msg_queue * msq, int cmd)
{
    return RESTRICTIVE_STACKED(msg_queue_msgctl, (msq, cmd));
}

static int stacker_msg_queue_msgsnd(struct msg_queue * msq, struct msg_msg * msg, int msqflg)
{
    return RESTRICTIVE_STACKED(msg_queue_msgsnd, (msq, msg, msqflg));
}

static int stacker_msg_queue_msgrcv(struct msg_queue * msq, struct msg_msg * msg, struct task_struct * target, long type, int mode)
{
    return RESTRICTIVE_STACKED(msg_queue_msgrcv, (msq, msg, target, type, mode));
}

static int stacker_shm_alloc_security(struct shmid_kernel * shp)
{
    return ALLOC_STACKED(shm_alloc_security, (shp), shm_free_security, (shp));
}

static void stacker_shm_free_security(struct shmid_kernel * shp)
{
    ALL_STACKED(shm_free_security, (shp));
}

static int stacker_shm_associate(struct shmid_kernel * shp, int shmflg)
{
    return RESTRICTIVE_STACKED(shm_associate, (shp, shmflg));
}

static int stacker_shm_shmctl(struct shmid_kernel * shp, int cmd)
{
    return RESTRICTIVE_STACKED(shm_shmctl, (shp, cmd));
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,7)
static int stacker_shm_shmat(struct shmid_kernel * shp, char __user *shmaddr, int shmflg)
{
    return RESTRICTIVE_STACKED(shm_shmat, (shp, shmaddr, shmflg));
}
#else
static int stacker_shm_shmat(struct shmid_kernel * shp, char *shmaddr, int shmflg)
{
    return RESTRICTIVE_STACKED(shm_shmat, (shp, shmaddr, shmflg));
}
#endif

static int stacker_sem_alloc_security(struct sem_array * sma)
{
    return ALLOC_STACKED(sem_alloc_security, (sma), sem_free_security, (sma));
}

static void stacker_sem_free_security(struct sem_array * sma)
{
    ALL_STACKED(sem_free_security, (sma));
}

static int stacker_sem_associate(struct sem_array * sma, int semflg)
{
    return RESTRICTIVE_STACKED(sem_associate, (sma, semflg));
}

static int stacker_sem_semctl(struct sem_array * sma, int cmd)
{
    return RESTRICTIVE_STACKED(sem_semctl, (sma, cmd));
}

static int stacker_sem_semop(struct sem_array * sma, struct sembuf * sops, unsigned nsops, int alter)
{
    return RESTRICTIVE_STACKED(sem_semop, (sma, sops, nsops, alter));
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,8)
static int stacker_netlink_send(struct sock * sk, struct sk_buff * skb)
{
    return RESTRICTIVE_STACKED(netlink_send, (sk, skb));
}
#else
static int stacker_netlink_send(struct sk_buff * skb)
{
    return RESTRICTIVE_STACKED(netlink_send, (skb));
}
#endif

static int stacker_netlink_recv(struct sk_buff * skb)
{
    return RESTRICTIVE_STACKED(netlink_recv, (skb));
}

static void stacker_d_instantiate(struct dentry *dentry, struct inode *inode)
{
    ALL_STACKED(d_instantiate, (dentry, inode));
}

static int stacker_getprocattr(struct task_struct *p, char *name, void *value, size_t size)
{
    return RESTRICTIVE_STACKED(getprocattr, (p, name, value, size));
}

static int stacker_setprocattr(struct task_struct *p, char *name, void *value, size_t size)
{
    return RESTRICTIVE_STACKED(setprocattr, (p, name, value, size));
}

#ifdef CONFIG_SECURITY_NETWORK
static int stacker_unix_stream_connect(struct socket * sock, struct socket * other, struct sock * newsk)
{
    return RESTRICTIVE_STACKED(unix_stream_connect, (sock, other, newsk));
}

static int stacker_unix_may_send(struct socket * sock, struct socket * other)
{
    return RESTRICTIVE_STACKED(unix_may_send, (sock, other));
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,6)) || defined TALPA_HAS_266_LSM
static int stacker_socket_create(int family, int type, int protocol, int kern)
{
    return RESTRICTIVE_STACKED(socket_create, (family, type, protocol, kern));
}

static void stacker_socket_post_create(struct socket * sock, int family, int type, int protocol, int kern)
{
    ALL_STACKED(socket_post_create, (sock, family, type, protocol, kern));
}
#else
static int stacker_socket_create(int family, int type, int protocol)
{
    return RESTRICTIVE_STACKED(socket_create, (family, type, protocol));
}

static void stacker_socket_post_create(struct socket * sock, int family, int type, int protocol)
{
    ALL_STACKED(socket_post_create, (sock, family, type, protocol));
}
#endif

static int stacker_socket_bind(struct socket * sock, struct sockaddr * address, int addrlen)
{
    return RESTRICTIVE_STACKED(socket_bind, (sock, address, addrlen));
}

static int stacker_socket_connect(struct socket * sock, struct sockaddr * address, int addrlen)
{
    return RESTRICTIVE_STACKED(socket_connect, (sock, address, addrlen));
}

static int stacker_socket_listen(struct socket * sock, int backlog)
{
    return RESTRICTIVE_STACKED(socket_listen, (sock, backlog));
}

static int stacker_socket_accept(struct socket * sock, struct socket * newsock)
{
    return RESTRICTIVE_STACKED(socket_accept, (sock, newsock));
}

static void stacker_socket_post_accept(struct socket * sock, struct socket * newsock)
{
    ALL_STACKED(socket_post_accept, (sock, newsock));
}

static int stacker_socket_sendmsg(struct socket * sock, struct msghdr * msg, int size)
{
    return RESTRICTIVE_STACKED(socket_sendmsg, (sock, msg, size));
}

static int stacker_socket_recvmsg(struct socket * sock, struct msghdr * msg, int size, int flags)
{
    return RESTRICTIVE_STACKED(socket_recvmsg, (sock, msg, size, flags));
}

static int stacker_socket_getsockname(struct socket * sock)
{
    return RESTRICTIVE_STACKED(socket_getsockname, (sock));
}

static int stacker_socket_getpeername(struct socket * sock)
{
    return RESTRICTIVE_STACKED(socket_getpeername, (sock));
}

static int stacker_socket_getsockopt(struct socket * sock, int level, int optname)
{
    return RESTRICTIVE_STACKED(socket_getsockopt, (sock, level, optname));
}

static int stacker_socket_setsockopt(struct socket * sock, int level, int optname)
{
    return RESTRICTIVE_STACKED(socket_setsockopt, (sock, level, optname));
}

static int stacker_socket_shutdown(struct socket * sock, int how)
{
    return RESTRICTIVE_STACKED(socket_shutdown, (sock, how));
}

static int stacker_socket_sock_rcv_skb(struct sock * sk, struct sk_buff * skb)
{
    return RESTRICTIVE_STACKED(socket_sock_rcv_skb, (sk, skb));
}

  #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,2)
static int stacker_socket_getpeersec(struct socket *sock, char __user *optval, int __user *optlen, unsigned len)
{
    return RESTRICTIVE_STACKED(socket_getpeersec, (sock, optval, optlen, len));
}

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,15)
static int stacker_sk_alloc_security(struct sock *sk, int family, gfp_t priority)
    #else
static int stacker_sk_alloc_security(struct sock *sk, int family, int priority)
    #endif
{
    return ALLOC_STACKED(sk_alloc_security, (sk, family, priority), sk_free_security, (sk));
}

static void stacker_sk_free_security(struct sock *sk)
{
    ALL_STACKED(sk_free_security, (sk));
}
  #endif

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
static unsigned int stacker_sk_getsid(struct sock *sk, struct flowi *fl, u8 dir)
{
    return RETURN_ONE_STACKED(sk_getsid, unsigned int, (sk, fl, dir));
}
    #endif

#endif  /* CONFIG_SECURITY_NETWORK */

#ifdef CONFIG_SECURITY_NETWORK_XFRM

static int stacker_xfrm_policy_alloc_security(struct xfrm_policy *xp, struct xfrm_user_sec_ctx *sec_ctx)
{
    return ALLOC_STACKED(xfrm_policy_alloc_security, (xp, sec_ctx), xfrm_policy_free_security, (xp));
}

static int stacker_xfrm_policy_clone_security(struct xfrm_policy *old, struct xfrm_policy *new)
{
    return ALLOC_STACKED(xfrm_policy_clone_security, (old, new), xfrm_policy_free_security, (new));
}

static void stacker_xfrm_policy_free_security(struct xfrm_policy *xp)
{
    ALL_STACKED(xfrm_policy_free_security, (xp));
}

static int stacker_xfrm_state_alloc_security(struct xfrm_state *x, struct xfrm_user_sec_ctx *sec_ctx)
{
    return ALLOC_STACKED(xfrm_state_alloc_security, (x, sec_ctx), xfrm_state_free_security, (x));
}

static void stacker_xfrm_state_free_security(struct xfrm_state *x)
{
    ALL_STACKED(xfrm_state_free_security, (x));
}

static int stacker_xfrm_policy_lookup(struct xfrm_policy *xp, u32 sk_sid, u8 dir)
{
    return RESTRICTIVE_STACKED(xfrm_policy_lookup, (xp, sk_sid, dir));
}

#endif  /* CONFIG_SECURITY_NETWORK_XFRM */

#ifdef CONFIG_KEYS

static int stacker_key_alloc(struct key *key)
{
    return ALLOC_STACKED(key_alloc, (key), key_free, (key));
}

static void stacker_key_free(struct key *key)
{
    ALL_STACKED(key_free, (key));
}

static int stacker_key_permission(key_ref_t key_ref, struct task_struct *context, key_perm_t perm)
{
    return RESTRICTIVE_STACKED(key_permission, (key_ref, context, perm));
}

#endif  /* CONFIG_KEYS */

struct security_operations stacker_ops = {
    .register_security =    stacker_register_security,
    .unregister_security =  stacker_unregister_security,
    .ptrace =               stacker_ptrace,
    .capget =               stacker_capget,
    .capset_check =         stacker_capset_check,
    .capset_set =           stacker_capset_set,
    .acct =                 stacker_acct,
    .sysctl =               stacker_sysctl,
    .capable =              stacker_capable,
    .quotactl =             stacker_quotactl,
    .quota_on =             stacker_quota_on,
    .syslog =               stacker_syslog,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
    .settime =              stacker_settime,
#endif
    .vm_enough_memory =     stacker_vm_enough_memory,

    .bprm_alloc_security =  stacker_bprm_alloc_security,
    .bprm_free_security =   stacker_bprm_free_security,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,6)) || defined TALPA_HAS_266_LSM
    .bprm_apply_creds =     stacker_bprm_apply_creds,
#else
    .bprm_compute_creds =   stacker_bprm_compute_creds,
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
    .bprm_post_apply_creds =stacker_bprm_post_apply_creds,
#endif
    .bprm_set_security =    stacker_bprm_set_security,
    .bprm_check_security =  stacker_bprm_check_security,
    .bprm_secureexec =      stacker_bprm_secureexec,

    .sb_alloc_security =    stacker_sb_alloc_security,
    .sb_free_security =     stacker_sb_free_security,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,3)
    .sb_copy_data =         stacker_sb_copy_data,
#endif
    .sb_kern_mount =        stacker_sb_kern_mount,
    .sb_statfs =            stacker_sb_statfs,
    .sb_mount =             stacker_sb_mount,
    .sb_check_sb =          stacker_sb_check_sb,
    .sb_umount =            stacker_sb_umount,
    .sb_umount_close =      stacker_sb_umount_close,
    .sb_umount_busy =       stacker_sb_umount_busy,
    .sb_post_remount =      stacker_sb_post_remount,
    .sb_post_mountroot =    stacker_sb_post_mountroot,
    .sb_post_addmount =     stacker_sb_post_addmount,
    .sb_pivotroot =         stacker_sb_pivotroot,
    .sb_post_pivotroot =    stacker_sb_post_pivotroot,

    .inode_alloc_security = stacker_inode_alloc_security,
    .inode_free_security =  stacker_inode_free_security,
    .inode_create =         stacker_inode_create,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
    .inode_init_security =  stacker_inode_init_security,
#else
    .inode_post_create =    stacker_inode_post_create,
    .inode_post_link =      stacker_inode_post_link,
    .inode_post_symlink =   stacker_inode_post_symlink,
    .inode_post_mkdir =     stacker_inode_post_mkdir,
    .inode_post_mknod =     stacker_inode_post_mknod,
    .inode_post_rename =    stacker_inode_post_rename,
#endif
    .inode_link =           stacker_inode_link,
    .inode_unlink =         stacker_inode_unlink,
    .inode_symlink =        stacker_inode_symlink,
    .inode_mkdir =          stacker_inode_mkdir,
    .inode_rmdir =          stacker_inode_rmdir,
    .inode_mknod =          stacker_inode_mknod,
    .inode_rename =         stacker_inode_rename,
    .inode_readlink =       stacker_inode_readlink,
    .inode_follow_link =    stacker_inode_follow_link,
    .inode_permission =     stacker_inode_permission,
    .inode_setattr =        stacker_inode_setattr,
    .inode_getattr =        stacker_inode_getattr,
    .inode_delete =         stacker_inode_delete,
    .inode_setxattr =       stacker_inode_setxattr,
    .inode_post_setxattr =  stacker_inode_post_setxattr,
    .inode_getxattr =       stacker_inode_getxattr,
    .inode_listxattr =      stacker_inode_listxattr,
    .inode_removexattr =    stacker_inode_removexattr,
    .inode_getsecurity =    stacker_inode_getsecurity,
    .inode_setsecurity =    stacker_inode_setsecurity,
    .inode_listsecurity =   stacker_inode_listsecurity,

    .file_permission =      stacker_file_permission,
    .file_alloc_security =  stacker_file_alloc_security,
    .file_free_security =   stacker_file_free_security,
    .file_ioctl =           stacker_file_ioctl,
    .file_mmap =            stacker_file_mmap,
    .file_mprotect =        stacker_file_mprotect,
    .file_lock =            stacker_file_lock,
    .file_fcntl =           stacker_file_fcntl,
    .file_set_fowner =      stacker_file_set_fowner,
    .file_send_sigiotask =  stacker_file_send_sigiotask,
    .file_receive =         stacker_file_receive,

    .task_create =              stacker_task_create,
    .task_alloc_security =      stacker_task_alloc_security,
    .task_free_security =       stacker_task_free_security,
    .task_setuid =              stacker_task_setuid,
    .task_post_setuid =         stacker_task_post_setuid,
    .task_setgid =              stacker_task_setgid,
    .task_setpgid =             stacker_task_setpgid,
    .task_getpgid =             stacker_task_getpgid,
    .task_getsid =              stacker_task_getsid,
    .task_setgroups =           stacker_task_setgroups,
    .task_setnice =             stacker_task_setnice,
    .task_setrlimit =           stacker_task_setrlimit,
    .task_setscheduler =        stacker_task_setscheduler,
    .task_getscheduler =        stacker_task_getscheduler,
    .task_kill =                stacker_task_kill,
    .task_wait =                stacker_task_wait,
    .task_prctl =               stacker_task_prctl,
    .task_reparent_to_init =    stacker_task_reparent_to_init,
    .task_to_inode =            stacker_task_to_inode,


    .ipc_permission =   stacker_ipc_permission,

    .msg_msg_alloc_security =   stacker_msg_msg_alloc_security,
    .msg_msg_free_security =    stacker_msg_msg_free_security,
    .msg_queue_alloc_security = stacker_msg_queue_alloc_security,
    .msg_queue_free_security =  stacker_msg_queue_free_security,
    .msg_queue_associate =      stacker_msg_queue_associate,
    .msg_queue_msgctl =         stacker_msg_queue_msgctl,
    .msg_queue_msgsnd =         stacker_msg_queue_msgsnd,
    .msg_queue_msgrcv =         stacker_msg_queue_msgrcv,

    .shm_alloc_security =   stacker_shm_alloc_security,
    .shm_free_security =    stacker_shm_free_security,
    .shm_associate =        stacker_shm_associate,
    .shm_shmctl =           stacker_shm_shmctl,
    .shm_shmat =            stacker_shm_shmat,

    .sem_alloc_security =   stacker_sem_alloc_security,
    .sem_free_security =    stacker_sem_free_security,
    .sem_associate =        stacker_sem_associate,
    .sem_semctl =           stacker_sem_semctl,
    .sem_semop =            stacker_sem_semop,

    .netlink_send = stacker_netlink_send,
    .netlink_recv = stacker_netlink_recv,

    .d_instantiate =    stacker_d_instantiate,

    .getprocattr =  stacker_getprocattr,
    .setprocattr =  stacker_setprocattr,

#ifdef CONFIG_SECURITY_NETWORK
    .unix_stream_connect =  stacker_unix_stream_connect,
    .unix_may_send =        stacker_unix_may_send,

    .socket_create =        stacker_socket_create,
    .socket_post_create =   stacker_socket_post_create,
    .socket_bind =          stacker_socket_bind,
    .socket_connect =       stacker_socket_connect,
    .socket_listen =        stacker_socket_listen,
    .socket_accept =        stacker_socket_accept,
    .socket_post_accept =   stacker_socket_post_accept,
    .socket_sendmsg =       stacker_socket_sendmsg,
    .socket_recvmsg =       stacker_socket_recvmsg,
    .socket_getsockname =   stacker_socket_getsockname,
    .socket_getpeername =   stacker_socket_getpeername,
    .socket_getsockopt =    stacker_socket_getsockopt,
    .socket_setsockopt =    stacker_socket_setsockopt,
    .socket_shutdown =      stacker_socket_shutdown,
    .socket_sock_rcv_skb =  stacker_socket_sock_rcv_skb,
  #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,2)
    .socket_getpeersec =    stacker_socket_getpeersec,

    .sk_alloc_security =    stacker_sk_alloc_security,
    .sk_free_security =     stacker_sk_free_security,
  #endif
  #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
    .sk_getsid =                stacker_sk_getsid,
  #endif

#endif

#ifdef CONFIG_SECURITY_NETWORK_XFRM
    .xfrm_policy_alloc_security =   stacker_xfrm_policy_alloc_security,
    .xfrm_policy_clone_security =   stacker_xfrm_policy_clone_security,
    .xfrm_policy_free_security =    stacker_xfrm_policy_free_security,
    .xfrm_state_alloc_security =    stacker_xfrm_state_alloc_security,
    .xfrm_state_free_security =     stacker_xfrm_state_free_security,
    .xfrm_policy_lookup =           stacker_xfrm_policy_lookup,
#endif

#ifdef CONFIG_KEYS
    .key_alloc =            stacker_key_alloc,
    .key_free =             stacker_key_free,
    .key_permission =       stacker_key_permission,
#endif
};

static int __init stacker_init(void)
{
    int ret;

    ret = register_security(&dummy_ops);
    if ( ret )
    {
        err("Failed to register as a primary security module!");
        return ret;
    }

    ret = unregister_security(&dummy_ops);
    if ( ret )
    {
        err("Failed to unregister!");
        return ret;
    }

    ret = register_security(&stacker_ops);
    if ( ret )
    {
        err("Failed to unregister as a primary security module!");
        return ret;
    }

    return 0;
}

static void __exit stacker_exit(void)
{
    if ( unregister_security(&stacker_ops) )
    {
        err("Failed to unregister!");
    }
}


module_init (stacker_init);
module_exit (stacker_exit);

MODULE_DESCRIPTION("Enables stacking of multiple LSM modules.");
MODULE_AUTHOR("Sophos Plc");
MODULE_LICENSE("GPL");

/*
 * End of stacker.c
 */

