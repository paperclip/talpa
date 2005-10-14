/*
 * talpa_syscallhook.c
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
#include <linux/wait.h>
#include <asm/atomic.h>
#include <linux/sched.h>
#include <linux/smp_lock.h>
#include <linux/slab.h>
#include <linux/unistd.h>
#include <linux/fs.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,3)
#include <linux/syscalls.h>
#endif
#include <linux/ptrace.h>
#include <linux/moduleparam.h>
#endif

#include "platforms/linux/talpa_syscallhook.h"



#ifdef TALPA_ID
const char talpa_id[] = "$TALPA_ID:" TALPA_ID;
#endif

#define err(format, arg...) printk(KERN_ERR "talpa-syscallhook: " format "\n" , ## arg)
#define warn(format, arg...) printk(KERN_WARNING "talpa-syscallhook: " format "\n" , ## arg)
#define notice(format, arg...) printk(KERN_NOTICE "talpa-syscallhook: " format "\n" , ## arg)
#define info(format, arg...) printk(KERN_INFO "talpa-syscallhook: " format "\n" , ## arg)
#ifdef DEBUG
#define dbg(format, arg...) printk(KERN_DEBUG "TALPA [" __FILE__ " ### %s] " format "\n" , __FUNCTION__, ## arg)
#else
#define dbg(format, arg...) do {} while (0)
#endif

#if __GNUC__ == 2 && __GNUC_MINOR__ < 96
#define __builtin_expect(x, expected_value) (x)
#endif

#ifndef likely
#define likely(x)       __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x)     __builtin_expect(!!(x), 0)
#endif

#ifndef MODULE_LICENSE
#define MODULE_LICENSE(x) const char module_license[] = x
#endif

static atomic_t usecnt = ATOMIC_INIT(0);
static struct talpa_syscall_operations* interceptor;
static DECLARE_WAIT_QUEUE_HEAD(unregister_wait);

static asmlinkage long (*orig_open)(const char* filename, int flags, int mode);
static asmlinkage long (*orig_close)(unsigned int fd);
static asmlinkage long (*orig_uselib)(const char* library);
#ifdef TALPA_EXECVE_SUPPORT
static asmlinkage int (*orig_execve)(struct pt_regs regs);
#endif
static asmlinkage long (*orig_mount)(char* dev_name, char* dir_name, char* type, unsigned long flags, void* data);
static asmlinkage long (*orig_umount)(char* name);
static asmlinkage long (*orig_umount2)(char* name, int flags);

/*
 * Hooking mask:
 * o = open
 * c = close
 * l = uselib
 * e = execve
 * m = mount
 * u = umount
 */
#ifdef TALPA_EXECVE_SUPPORT
static char *hook_mask = "oclemu";
#else
static char *hook_mask = "oclmu";
#endif

/*
 * Exported interface
 */

int talpa_syscallhook_register(struct talpa_syscall_operations* ops)
{
    if ( interceptor )
    {
        return -EBUSY;
    }

    if ( !ops )
    {
        return -EINVAL;
    }

    atomic_inc(&usecnt);
    interceptor = ops;

    return 0;
}

void talpa_syscallhook_unregister(struct talpa_syscall_operations* ops)
{
    if ( (!interceptor) || (!ops) || (ops != interceptor) )
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

/* Function below, which finds the hidden system call table,
   is borrowed from the Dazuko project. It is confirmed to work
   on both patched 2.4 and vanilla 2.6 kernels. */
#ifdef TALPA_HIDDEN_SYSCALLS
void **sys_call_table;

static void** talpa_find_syscall_table(void)
{
    unsigned long ptr;
    extern int loops_per_jiffy;
    unsigned long *p;

    for ( ptr = (unsigned long)&loops_per_jiffy; ptr < (unsigned long)&boot_cpu_data; ptr += sizeof(void *) )
    {
        p = (unsigned long *)ptr;
        if ( p[6] == (unsigned long)sys_close )
        {
            return (void **)p;
        }
    }

    return NULL;
}
#else
extern void *sys_call_table[];
#endif

/*
 * Hooks
 */

static asmlinkage long talpa_open(const char* filename, int flags, int mode)
{
    struct talpa_syscall_operations* ops;
    int fd;


    atomic_inc(&usecnt);

    fd = orig_open(filename, flags, mode);

    if ( unlikely( fd < 0 ) )
    {
        goto out;
    }

    ops = interceptor;

    if ( likely( ops != NULL ) )
    {
        int err;


        err = ops->open_post(fd);
        if ( unlikely ( err < 0 ) )
        {
            orig_close(fd);
            fd = err;
        }
    }

out:
    if ( unlikely( atomic_dec_and_test(&usecnt) != 0 ) )
    {
        wake_up(&unregister_wait);
    }

    return fd;
}

static asmlinkage long talpa_close(unsigned int fd)
{
    struct talpa_syscall_operations* ops;
    int err;


    atomic_inc(&usecnt);

    ops = interceptor;

    if ( likely( ops != NULL ) )
    {
        ops->close_pre(fd);
    }

    err = orig_close(fd);

    if ( unlikely( atomic_dec_and_test(&usecnt) != 0 ) )
    {
        wake_up(&unregister_wait);
    }

    return err;
}

static asmlinkage long talpa_uselib(const char* library)
{
    struct talpa_syscall_operations* ops;
    int err = 0;

    atomic_inc(&usecnt);

    ops = interceptor;

    if ( likely( ops != NULL ) )
    {
        err = ops->uselib_pre(library);
        if ( unlikely( err < 0 ) )
        {
            goto out;
        }
    }

    err = orig_uselib(library);

out:
    if ( unlikely( atomic_dec_and_test(&usecnt) != 0 ) )
    {
        wake_up(&unregister_wait);
    }

    return err;
}

/* This is a original sys_execve with talpa code injected */
#ifdef TALPA_EXECVE_SUPPORT
static asmlinkage int talpa_execve(struct pt_regs regs)
{
    int error;
    char * filename;
    struct talpa_syscall_operations* ops;

    atomic_inc(&usecnt);
    ops = interceptor;

    filename = getname((char *) regs.ebx);
    error = PTR_ERR(filename);
    if (IS_ERR(filename))
        goto out;

    if ( likely( ops != NULL ) )
    {
        error = ops->execve_pre(filename);
        if ( unlikely( error < 0 ))
        {
            goto out2;
        }
    }

    error = do_execve(filename, (char **) regs.ecx, (char **) regs.edx, &regs);
    if (error == 0)
        current->ptrace &= ~PT_DTRACE;
out2:
    putname(filename);
out:
    if ( unlikely( atomic_dec_and_test(&usecnt) != 0 ) )
    {
        wake_up(&unregister_wait);
    }

    return error;
}
#else
#warning "execve is not implemented on this kernel/platform!"
#endif

static asmlinkage long talpa_mount(char* dev_name, char* dir_name, char* type, unsigned long flags, void* data)
{
    struct talpa_syscall_operations* ops;
    int err;


    atomic_inc(&usecnt);

    ops = interceptor;

    if ( likely( ops != NULL ) )
    {
        err = ops->mount_pre(dev_name, dir_name, type, flags, data);
        if ( unlikely( err < 0 ) )
        {
            goto out;
        }
    }

    err = orig_mount(dev_name, dir_name, type, flags, data);

    if ( likely( ops != NULL ) )
    {
        ops->mount_post(err, dev_name, dir_name, type, flags, data);
    }
out:
    if ( unlikely( atomic_dec_and_test(&usecnt) != 0 ) )
    {
        wake_up(&unregister_wait);
    }

    return err;
}

static asmlinkage long talpa_umount(char* name)
{
    struct talpa_syscall_operations* ops;
    int err;


    atomic_inc(&usecnt);

    ops = interceptor;

    if ( likely( ops != NULL ) )
    {
        ops->umount_pre(name, 0);
    }

    err = orig_umount(name);

    if ( likely( ops != NULL ) )
    {
        ops->umount_post(err, name, 0);
    }

    if ( unlikely( atomic_dec_and_test(&usecnt) != 0 ) )
    {
        wake_up(&unregister_wait);
    }

    return err;
}

static asmlinkage long talpa_umount2(char* name, int flags)
{
    struct talpa_syscall_operations* ops;
    int err;


    atomic_inc(&usecnt);

    ops = interceptor;

    if ( likely( ops != NULL ) )
    {
        ops->umount_pre(name, flags);
    }

    err = orig_umount2(name, flags);

    if ( likely( ops != NULL ) )
    {
        ops->umount_post(err, name, flags);
    }

    if ( unlikely( atomic_dec_and_test(&usecnt) != 0 ) )
    {
        wake_up(&unregister_wait);
    }

    return err;
}

/*
 * Module init and exit
 */

static int __init talpa_syscallhook_init(void)
{
#ifdef TALPA_HIDDEN_SYSCALLS
    sys_call_table = talpa_find_syscall_table();
    if (sys_call_table == NULL)
    {
        err("Cannot find syscall table!");
        return -ESRCH;
    }
#endif

    lock_kernel();
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    fsync_dev(0);
#endif

    orig_open = sys_call_table[__NR_open];
    orig_close = sys_call_table[__NR_close];
    orig_uselib = sys_call_table[__NR_uselib];
    orig_mount = sys_call_table[__NR_mount];

#if defined CONFIG_X86
 #if defined CONFIG_X86_64
    orig_umount2 = sys_call_table[__NR_umount2];
 #else
    orig_umount = sys_call_table[__NR_umount];
    orig_umount2 = sys_call_table[__NR_umount2];
 #endif
#else
 #error "Architecture currently not supported!"
#endif

#ifdef TALPA_EXECVE_SUPPORT
    orig_execve = sys_call_table[__NR_execve];
#endif

    if ( strchr(hook_mask, 'o') )
    {
        sys_call_table[__NR_open] = talpa_open;
    }

    if ( strchr(hook_mask, 'c') )
    {
        sys_call_table[__NR_close] = talpa_close;
    }

    if ( strchr(hook_mask, 'l') )
    {
        sys_call_table[__NR_uselib] = talpa_uselib;
    }

    if ( strchr(hook_mask, 'm') )
    {
        sys_call_table[__NR_mount] = talpa_mount;
    }

    if ( strchr(hook_mask, 'u') )
    {
#if defined CONFIG_X86
 #if defined CONFIG_X86_64
        sys_call_table[__NR_umount2] = talpa_umount2;
 #else
        sys_call_table[__NR_umount] = talpa_umount;
        sys_call_table[__NR_umount2] = talpa_umount2;
 #endif
#endif
    }

#ifdef TALPA_EXECVE_SUPPORT
    if ( strchr(hook_mask, 'e') )
    {
        sys_call_table[__NR_execve] = talpa_execve;
    }
#endif

    unlock_kernel();

    dbg("Hooked [%s]", hook_mask);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    inter_module_register("talpa_syscallhook_register", THIS_MODULE, (const void *)talpa_syscallhook_register);
    inter_module_register("talpa_syscallhook_unregister", THIS_MODULE, (const void *)talpa_syscallhook_unregister);
#endif

    return 0;
}

static void __exit talpa_syscallhook_exit(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    inter_module_unregister("talpa_syscallhook_register");
    inter_module_unregister("talpa_syscallhook_unregister");
#endif

    lock_kernel();
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    fsync_dev(0);
#endif

    sys_call_table[__NR_open] = orig_open;
    sys_call_table[__NR_close] = orig_close;
    sys_call_table[__NR_uselib] = orig_uselib;
    sys_call_table[__NR_mount] = orig_mount;

#if defined CONFIG_X86
 #if defined CONFIG_X86_64
    sys_call_table[__NR_umount2] = orig_umount2;
 #else
    sys_call_table[__NR_umount] = orig_umount;
    sys_call_table[__NR_umount2] = orig_umount2;
 #endif
#endif

#ifdef TALPA_EXECVE_SUPPORT
    sys_call_table[__NR_execve] = orig_execve;
#endif

    unlock_kernel();

    /* Now wait for a last caller to exit */
    wait_event(unregister_wait, atomic_read(&usecnt) == 0);

    dbg("Unhooked");
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)

EXPORT_SYMBOL(talpa_syscallhook_register);
EXPORT_SYMBOL(talpa_syscallhook_unregister);

module_param(hook_mask, charp, 0400);

#else

EXPORT_SYMBOL_NOVERS(talpa_syscallhook_register);
EXPORT_SYMBOL_NOVERS(talpa_syscallhook_unregister);

MODULE_PARM(hook_mask, "s");

#endif /* >= 2.6.0 */

#ifdef TALPA_EXECVE_SUPPORT
MODULE_PARM_DESC(hook_mask, "list of system calls to hook where o=open, c=close, l=uselib, e=execve, m=mount and u=umount (default: oclemu)");
#else
MODULE_PARM_DESC(hook_mask, "list of system calls to hook where o=open, c=close, l=uselib, m=mount and u=umount (default: oclmu)");
#endif

module_init(talpa_syscallhook_init);
module_exit(talpa_syscallhook_exit);

MODULE_DESCRIPTION("Hooks into the syscall table and provides hooking interface for one module.");
MODULE_AUTHOR("Sophos Plc");
MODULE_LICENSE("GPL");

/*
 * End of talpa_syscallhook.c
 */

