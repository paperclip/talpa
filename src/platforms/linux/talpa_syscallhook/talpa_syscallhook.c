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

#ifdef TALPA_VERSION
const char talpa_version[] = "$TALPA_VERSION:" TALPA_VERSION;
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

#if defined TALPA_EXECVE_SUPPORT && defined CONFIG_IA32_EMULATION
  #undef TALPA_EXECVE_SUPPORT
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
#if defined CONFIG_X86 && !defined CONFIG_X86_64
static asmlinkage long (*orig_umount)(char* name);
#endif
static asmlinkage long (*orig_umount2)(char* name, int flags);

#ifdef CONFIG_IA32_EMULATION
static asmlinkage long (*orig_open_32)(const char* filename, int flags, int mode);
static asmlinkage long (*orig_close_32)(unsigned int fd);
  #ifdef CONFIG_IA32_AOUT
static asmlinkage long (*orig_uselib_32)(const char* library);
  #endif
static asmlinkage long (*orig_mount_32)(char* dev_name, char* dir_name, char* type, unsigned long flags, void* data);
static asmlinkage long (*orig_umount_32)(char* name);
static asmlinkage long (*orig_umount2_32)(char* name, int flags);
#endif

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

static unsigned long override_syscall_table;
static unsigned long override_syscall32_table;

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

#if defined CONFIG_X86 && (!defined CONFIG_X86_64 || CONFIG_IA32_EMULATION)
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

  #ifdef CONFIG_IA32_EMULATION
    err = orig_umount_32(name);
  #else
    err = orig_umount(name);
  #endif

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
#endif

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
 * System call table helpers
 */

#ifdef TALPA_HIDDEN_SYSCALLS
static void **sys_call_table;

  #ifdef CONFIG_IA32_EMULATION
static void **ia32_sys_call_table;
  #endif

/* Code below, which finds the hidden system call table,
   is borrowed from the ARLA project. It is confirmed to work
   on 2.6 (x86, x86_64) and patched 2.4 (x86) kernels. */

  #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
    #include <linux/kallsyms.h>
static void *lower_bound = &kernel_thread;
  #else
    #include <asm/pgtable.h>
static void *lower_bound = &empty_zero_page;
  #endif

const char * __attribute__((weak)) kallsyms_lookup(unsigned long addr, unsigned long *symbolsize, unsigned long *offset, char **modname, char *namebuf);

static void **get_start_addr(void)
{
  #ifdef CONFIG_X86_64
    return (void **)&tasklist_lock - 0x1000;
  #else
    return (void **)&init_mm;
  #endif
}

  #ifdef CONFIG_IA32_EMULATION
static void **get_start_addr_ia32(void)
{
    return (void **)&console_printk - 0x1000;
}
  #endif

static int kallsym_is_equal(unsigned long addr, const char *name)
{
    char namebuf[128];
    const char *retname;
    unsigned long size, offset;
    char *modname;


    retname = kallsyms_lookup(addr, &size, &offset, &modname, namebuf);

    if ( (retname != NULL) && (strcmp(name, retname) == 0) && (offset == 0) )
    {
        return 1;
    }

    return 0;
}

static int verify(void **p, const int zapped_syscalls[], const int unique_syscalls[], int symlookup)
{
    const int num_zapped_syscalls = (sizeof(zapped_syscalls)/sizeof(zapped_syscalls[0])) - 1;
    const int num_unique_syscalls = sizeof(unique_syscalls)/sizeof(unique_syscalls[0]);
    int i, s;


    /* Make sure that pointers are found at the right places */
    for ( i = 0; i < num_unique_syscalls; i++ )
    {
        for ( s = 0; s < 223; s++ )
        {
            if ( (p[s] == p[unique_syscalls[i]]) && (s != unique_syscalls[i]) )
            {
                return 0;
            }
        }
    }

    /* More checks... (not implemented system calls) */
    for ( i = 1; i < num_zapped_syscalls; i++ )
    {
        if ( p[zapped_syscalls[i]] != p[zapped_syscalls[0]] )
        {
            return 0;
        }
    }

    if ( symlookup && kallsyms_lookup && (   !kallsym_is_equal((unsigned long)p[__NR_close], "sys_close")
                                          || !kallsym_is_equal((unsigned long)p[__NR_chdir], "sys_chdir")) )
    {
        return 0;
    }

    return 1;
}

static int looks_good(void **p)
{
    if ( (*p <= (void*)lower_bound) || (*p >= (void*)p) )
    {
        return 0;
    }

    return 1;
}

static void **talpa_find_syscall_table(void **ptr, const int zapped_syscalls[], const int unique_syscalls[], int symlookup)
{
    void **limit;
    void **table = NULL;


    lower_bound = (void*)((unsigned long)lower_bound & ~0xfffff);

    for ( limit = ptr + 16 * 1024; ptr < limit && table == NULL; ptr++ )
    {
        int ok = 1;
        int i;


        for ( i = 0; i < 222; i++ )
        {
            if ( !looks_good(ptr + i) )
            {
                ok = 0;
                ptr = ptr + i;
                break;
            }
        }

        if ( ok && verify(ptr, zapped_syscalls, unique_syscalls, symlookup) )
        {
            table = ptr;
            break;
        }
    }

    if ( table == NULL )
    {
        return NULL;
    }

    return table;
}

#else
extern void *sys_call_table[];
#endif

/*
 * Module init and exit
 */

static int __init talpa_syscallhook_init(void)
{
#ifdef TALPA_HIDDEN_SYSCALLS
  #ifdef CONFIG_X86_64
    #ifdef CONFIG_IA32_EMULATION

      #define __NR_open_ia32      5
      #define __NR_close_ia32     6
      #define __NR_uselib_ia32    86
      #define __NR_mount_ia32     21
      #define __NR_umount_ia32    22
      #define __NR_umount2_ia32   52
      #define __NR_break_ia32     17
      #define __NR_stty_ia32      31
      #define __NR_gtty_ia32      32
      #define __NR_ftime_ia32     35
      #define __NR_prof_ia32      44
      #define __NR_lock_ia32      53
      #define __NR_mpx_ia32       56
      #define __NR_exit_ia32      1
      #define __NR_read_ia32      3
      #define __NR_write_ia32     4
      #define __NR_unlink_ia32    10

    const int unique_syscalls_ia32[] = { __NR_exit_ia32, __NR_mount_ia32, __NR_read_ia32, __NR_write_ia32, __NR_open_ia32, __NR_close_ia32, __NR_unlink_ia32 };
    const int zapped_syscalls_ia32[] = { __NR_break_ia32, __NR_stty_ia32, __NR_gtty_ia32, __NR_ftime_ia32, __NR_prof_ia32, __NR_lock_ia32, __NR_mpx_ia32, 0 };

    if ( override_syscall32_table )
    {
        ia32_sys_call_table = (void **)override_syscall32_table;
        info("Userspace specified ia32_sys_call_table at 0x%p", ia32_sys_call_table);
    }
    else
    {
        ia32_sys_call_table = talpa_find_syscall_table(get_start_addr_ia32(), zapped_syscalls_ia32, unique_syscalls_ia32, 0);
    }

    if ( ia32_sys_call_table == NULL )
    {
        err("Cannot find IA32 emulation syscall table!");
        return -ESRCH;
    }
    #endif

    const int unique_syscalls[] = { __NR_read, __NR_dup, __NR_open, __NR_close, __NR_mmap, __NR_exit, __NR_kill };
    const int zapped_syscalls[] = { __NR_uselib, __NR_create_module, __NR_get_kernel_syms, __NR_security, __NR_get_thread_area, __NR_epoll_wait_old, __NR_vserver, 0 };
  #elif CONFIG_X86
    const int unique_syscalls[] = { __NR_exit, __NR_mount, __NR_read, __NR_write, __NR_open, __NR_close, __NR_unlink };
    const int zapped_syscalls[] = { __NR_break, __NR_stty, __NR_gtty, __NR_ftime, __NR_prof, __NR_lock, __NR_mpx, 0 };
  #endif

    if ( override_syscall_table )
    {
        sys_call_table = (void **)override_syscall_table;
        info("Userspace specified sys_call_table at 0x%p", sys_call_table);
    }
    else
    {
        sys_call_table = talpa_find_syscall_table(get_start_addr(), zapped_syscalls, unique_syscalls, 1);
    }

    if ( sys_call_table == NULL )
    {
        err("Cannot find syscall table!");
        return -ESRCH;
    }
#endif

    lock_kernel();
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    fsync_dev(0);
#endif

#ifdef CONFIG_X86
    orig_open = sys_call_table[__NR_open];
    orig_close = sys_call_table[__NR_close];
  #ifdef TALPA_EXECVE_SUPPORT
    orig_execve = sys_call_table[__NR_execve];
  #endif
    orig_uselib = sys_call_table[__NR_uselib];
    orig_mount = sys_call_table[__NR_mount];
  #if defined CONFIG_X86_64
    orig_umount2 = sys_call_table[__NR_umount2];
    #ifdef CONFIG_IA32_EMULATION
    orig_open_32 = ia32_sys_call_table[__NR_open_ia32];
    orig_close_32 = ia32_sys_call_table[__NR_close_ia32];
      #ifdef CONFIG_IA32_AOUT
    orig_uselib_32 = ia32_sys_call_table[__NR_uselib_ia32];
      #endif
    orig_mount_32 = ia32_sys_call_table[__NR_mount_ia32];
    orig_umount_32 = ia32_sys_call_table[__NR_umount_ia32];
    orig_umount2_32 = ia32_sys_call_table[__NR_umount2_ia32];
    #endif
  #else
    orig_umount = sys_call_table[__NR_umount];
    orig_umount2 = sys_call_table[__NR_umount2];
  #endif
#else
  #error "Architecture currently not supported!"
#endif

    if ( strchr(hook_mask, 'o') )
    {
        sys_call_table[__NR_open] = talpa_open;
#ifdef CONFIG_IA32_EMULATION
        ia32_sys_call_table[__NR_open_ia32] = talpa_open;
#endif
    }

    if ( strchr(hook_mask, 'c') )
    {
        sys_call_table[__NR_close] = talpa_close;
#ifdef CONFIG_IA32_EMULATION
        ia32_sys_call_table[__NR_close_ia32] = talpa_close;
#endif
    }

    if ( strchr(hook_mask, 'l') )
    {
        sys_call_table[__NR_uselib] = talpa_uselib;
#if defined CONFIG_IA32_EMULATION && defined CONFIG_IA32_AOUT
        ia32_sys_call_table[__NR_uselib_ia32] = talpa_uselib;
#endif
    }

    if ( strchr(hook_mask, 'm') )
    {
        sys_call_table[__NR_mount] = talpa_mount;
#ifdef CONFIG_IA32_EMULATION
        ia32_sys_call_table[__NR_mount_ia32] = talpa_mount;
#endif
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
#ifdef CONFIG_IA32_EMULATION
        ia32_sys_call_table[__NR_umount_ia32] = talpa_umount;
        ia32_sys_call_table[__NR_umount2_ia32] = talpa_umount2;
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

#if defined CONFIG_X86
    sys_call_table[__NR_open] = orig_open;
    sys_call_table[__NR_close] = orig_close;
  #ifdef TALPA_EXECVE_SUPPORT
    sys_call_table[__NR_execve] = orig_execve;
  #endif
    sys_call_table[__NR_uselib] = orig_uselib;
    sys_call_table[__NR_mount] = orig_mount;
  #if defined CONFIG_X86_64
    sys_call_table[__NR_umount2] = orig_umount2;
    #ifdef CONFIG_IA32_EMULATION
    ia32_sys_call_table[__NR_open_ia32] = orig_open_32;
    ia32_sys_call_table[__NR_close_ia32] = orig_close_32;
      #ifdef CONFIG_IA32_AOUT
    ia32_sys_call_table[__NR_uselib_ia32] = orig_uselib_32;
      #endif
    ia32_sys_call_table[__NR_mount_ia32] = orig_mount_32;
    ia32_sys_call_table[__NR_umount_ia32] = orig_umount_32;
    ia32_sys_call_table[__NR_umount2_ia32] = orig_umount2_32;
    #endif
  #else
    sys_call_table[__NR_umount] = orig_umount;
    sys_call_table[__NR_umount2] = orig_umount2;
  #endif
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
module_param(override_syscall_table, ulong, 0400);
module_param(override_syscall32_table, ulong, 0400);

#else

EXPORT_SYMBOL_NOVERS(talpa_syscallhook_register);
EXPORT_SYMBOL_NOVERS(talpa_syscallhook_unregister);

MODULE_PARM(hook_mask, "s");
MODULE_PARM(override_syscall_table, "l");
MODULE_PARM(override_syscall32_table, "l");

#endif /* >= 2.6.0 */

#ifdef TALPA_EXECVE_SUPPORT
MODULE_PARM_DESC(hook_mask, "list of system calls to hook where o=open, c=close, l=uselib, e=execve, m=mount and u=umount (default: oclemu)");
#else
MODULE_PARM_DESC(hook_mask, "list of system calls to hook where o=open, c=close, l=uselib, m=mount and u=umount (default: oclmu)");
#endif
MODULE_PARM_DESC(override_syscall_table, "override value for the system call table address (normally autodetected)");
MODULE_PARM_DESC(override_syscall32_table, "override value for the ia32 emulation system call table address (normally autodetected)");

module_init(talpa_syscallhook_init);
module_exit(talpa_syscallhook_exit);

MODULE_DESCRIPTION("Hooks into the syscall table and provides hooking interface for one module.");
MODULE_AUTHOR("Sophos Plc");
MODULE_LICENSE("GPL");
#if defined TALPA_VERSION && defined MODULE_VERSION
MODULE_VERSION(TALPA_VERSION);
#endif


/*
 * End of talpa_syscallhook.c
 */

