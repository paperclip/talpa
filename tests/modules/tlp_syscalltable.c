/*
 * talpa_syscalltable.c
 *
 * TALPA Filesystem Interceptor
 *
 * Copyright(C) 2004-2008 Sophos Plc, Oxford, England.
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
#include <linux/sched.h>
#include <linux/unistd.h>
#include <linux/linkage.h>
#include <linux/smp_lock.h>
#include <linux/fs.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
  #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,3)
    #include <linux/syscalls.h>
  #endif
  #include <linux/ptrace.h>
#endif
#ifdef TALPA_HAS_RODATA
#include <asm/page.h>
#include <asm/cacheflush.h>
#endif

#define TALPA_SUBSYS "syscalltable"
#include "common/talpa.h"

static asmlinkage long (*orig_mount)(char* dev_name, char* dir_name, char* type, unsigned long flags, void* data);

static void talpa_syscallhook_unro(int rw);

#ifdef TALPA_HIDDEN_SYSCALLS
static unsigned long syscall_table = TALPA_SYSCALL_TABLE;
#endif

#ifdef TALPA_HAS_RODATA
static unsigned long rodata_start = TALPA_RODATA_START;
static unsigned long rodata_end = TALPA_RODATA_END;
#endif

#ifndef prevent_tail_call
# define prevent_tail_call(ret) do { } while (0)
#endif

void talpa_syscallhook_modify_start(void)
{
    lock_kernel();
    talpa_syscallhook_unro(1);
    unlock_kernel();
}

void talpa_syscallhook_modify_finish(void)
{
    lock_kernel();
    talpa_syscallhook_unro(0);
    unlock_kernel();
}

static asmlinkage long talpa_mount(char* dev_name, char* dir_name, char* type, unsigned long flags, void* data)
{
    long err;
    err = orig_mount(dev_name, dir_name, type, flags, data);
    prevent_tail_call(err);
    return err;
}

/*
 * System call table helpers
 */

#ifdef TALPA_HIDDEN_SYSCALLS
static void **sys_call_table;

/* Code below, which finds the hidden system call table,
   is borrowed from the ARLA project and modified.
   It is confirmed to work on 2.6 (x86, x86_64) and
   patched 2.4 (x86) kernels. */

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
  #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
    #ifdef CONFIG_SMP
    return (void **)&lock_kernel;
    #else
      #include <linux/mutex.h>
      #ifdef CONFIG_DEBUG_LOCK_ALLOC
    return (void **)&mutex_lock_nested;
      #else
    return (void **)&mutex_lock;
      #endif
    #endif
  #else
    #ifdef CONFIG_X86_64
    return (void **)&tasklist_lock - 0x4000;
    #else
    return (void **)&init_mm;
    #endif
  #endif
}

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

static int verify(void **p, const unsigned int unique_syscalls[], const unsigned int num_unique_syscalls, const unsigned int zapped_syscalls[], const unsigned int num_zapped_syscalls, int symlookup)
{
    unsigned int i, s;


    /* Check that not implemented system calls all point to the same address.
        This is where heuristic usually immediately fails. */
    for ( i = 1; i < num_zapped_syscalls; i++ )
    {
        if ( p[zapped_syscalls[i]] != p[zapped_syscalls[0]] )
        {
                dbg("  [0x%p] not same %u", p, zapped_syscalls[i]);
            return 0;
        }
    }

    /* Check that all different sysmte calls are really different */
    for ( i = 0; i < num_unique_syscalls; i++ )
    {
        for ( s = 0; s < 223; s++ )
        {
            if ( (p[s] == p[unique_syscalls[i]]) && (s != unique_syscalls[i]) )
            {
                dbg("  [0x%p] not unique %u", p, unique_syscalls[i]);
                return 0;
            }
        }
    }

    /* Lookup symbols (if we can) as a final check */
    if (    symlookup
         && kallsyms_lookup
         && !IS_ERR(kallsyms_lookup)
         && (    !kallsym_is_equal((unsigned long)p[__NR_close], "sys_close")
              || !kallsym_is_equal((unsigned long)p[__NR_chdir], "sys_chdir")) )
    {
        dbg("  [0x%p] lookup mismatch", p);
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

static void **talpa_find_syscall_table(void **ptr, const unsigned int unique_syscalls[], const unsigned int num_unique_syscalls, const unsigned int zapped_syscalls[], const unsigned int num_zapped_syscalls, int symlookup)
{
    void **limit = ptr + 0xa000;
    void **table = NULL;
#ifdef DEBUG
    unsigned int i;

    dbg_start();
    dbg_cont("unique: ");
    for ( i = 0; i < num_unique_syscalls; i++ )
    {
        dbg_cont("%u ", unique_syscalls[i]);
    }
    dbg_end();

    dbg_start();
    dbg_cont("zapped: ");
    for ( i = 0; i < num_zapped_syscalls; i++ )
    {
        dbg_cont("%u ", zapped_syscalls[i]);
    }
    dbg_end();

    dbg("scan from 0x%p to 0x%p", ptr, limit);
#endif

    lower_bound = (void*)((unsigned long)lower_bound & ~0xfffff);
    dbg("lower bound 0x%p", lower_bound);

    for ( ; ptr < limit && table == NULL; ptr++ )
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

        if ( ok && verify(ptr, unique_syscalls, num_unique_syscalls, zapped_syscalls, num_zapped_syscalls, symlookup) )
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

#ifndef TALPA_HAS_RODATA
static void talpa_syscallhook_unro(int rw)
{
    return;
}
#else /* defined TALPA_HAS_RODATA */

#ifdef TALPA_NEEDS_VA_CPA
static unsigned long *talpa_phys_base = (unsigned long *)TALPA_PHYS_BASE;

#define talpa_pa_symbol(x) \
        ({unsigned long v;  \
          asm("" : "=r" (v) : "0" (x)); \
          ((v - __START_KERNEL_map) + (*talpa_phys_base)); })

#define talpa_ka_to_cpa(adr) ((unsigned long)__va(talpa_pa_symbol(adr)))

#else /* NEEDS_VA_CPA */
#define talpa_ka_to_cpa(adr) ((unsigned long)adr)
#endif /* NEEDS_VA_CPA */

static void talpa_syscallhook_unro(int rw)
{
    unsigned long nr_pages = (rodata_end - rodata_start) / PAGE_SIZE;


  #ifdef TALPA_HAS_SET_PAGES
    #ifdef CONFIG_X86_64
    typedef int (*kfunc)(unsigned long addr, int numpages);
    kfunc set_memory_rwro;


    if ( rw )
    {
        set_memory_rwro  = (kfunc)TALPA_KFUNC_SET_MEMORY_RW;
    }
    else
    {
        set_memory_rwro  = (kfunc)TALPA_KFUNC_SET_MEMORY_RO;
    }

    set_memory_rwro(rodata_start, nr_pages);
    #elif CONFIG_X86
    typedef int (*kfunc)(struct page *page, int numpages);
    kfunc set_pages_rwro;


    if ( rw )
    {
        set_pages_rwro  = (kfunc)TALPA_KFUNC_SET_PAGES_RW;
    }
    else
    {
        set_pages_rwro  = (kfunc)TALPA_KFUNC_SET_PAGES_RO;
    }

    set_pages_rwro(virt_to_page(rodata_start), nr_pages);
    #endif
  #else /* HAS_SET_PAGES */
    #ifdef CONFIG_X86_64
    typedef int (*kfunc)(unsigned long addr, int numpages, pgprot_t prot);
    static kfunc talpa_change_page_attr_addr = (kfunc)TALPA_KFUNC_CHANGE_PAGE_ATTR_ADDR;

    if ( rw )
    {
        talpa_change_page_attr_addr(talpa_ka_to_cpa(rodata_start), nr_pages, PAGE_KERNEL);
    }
    else
    {
        talpa_change_page_attr_addr(talpa_ka_to_cpa(rodata_start), nr_pages, PAGE_KERNEL_RO);
    }
    #elif CONFIG_X86
    if ( rw )
    {
        change_page_attr(virt_to_page(rodata_start), nr_pages, PAGE_KERNEL);
    }
    else
    {
        change_page_attr(virt_to_page(rodata_start), nr_pages, PAGE_KERNEL_RO);
    }
    #endif

    global_flush_tlb();
  #endif
}
#endif /* HAS_RODATA */

#ifdef TALPA_HIDDEN_SYSCALLS
static int find_syscall_table(void)
{
    unsigned int num_unique_syscalls;
    unsigned int num_zapped_syscalls;
  #ifdef CONFIG_X86_64
    const unsigned int unique_syscalls[] = { __NR_read, __NR_dup, __NR_open, __NR_close, __NR_mmap, __NR_exit, __NR_kill };
    const unsigned int zapped_syscalls[] = { __NR_create_module, __NR_get_kernel_syms, __NR_security, __NR_get_thread_area, __NR_epoll_wait_old, __NR_vserver, 0 };
  #elif CONFIG_X86
    const unsigned int unique_syscalls[] = { __NR_exit, __NR_mount, __NR_read, __NR_write, __NR_open, __NR_close, __NR_unlink };
    const unsigned int zapped_syscalls[] = { __NR_break, __NR_stty, __NR_gtty, __NR_ftime, __NR_prof, __NR_lock, __NR_mpx, 0 };
  #endif

    num_unique_syscalls = sizeof(unique_syscalls)/sizeof(unique_syscalls[0]);
    num_zapped_syscalls = (sizeof(zapped_syscalls)/sizeof(zapped_syscalls[0])) - 1;

    if ( syscall_table )
    {
        sys_call_table = (void **)syscall_table;

        if ( verify(sys_call_table, unique_syscalls, num_unique_syscalls, zapped_syscalls, num_zapped_syscalls, 1) )
        {
            dbg("userspace specified sys_call_table at 0x%p", sys_call_table);
        }
        else
        {
            dbg("not a sys_call_table at 0x%p", sys_call_table);
            syscall_table = 0UL;
        }
    }

    /* If valid address wasn't supplied to us we'll try to autodetect it */
    if ( !syscall_table )
    {
        sys_call_table = talpa_find_syscall_table(get_start_addr(), unique_syscalls, num_unique_syscalls, zapped_syscalls, num_zapped_syscalls, 1);
        /* There was a case when start_addr and sys_call_table were not on the same byte allignment, so retry with toggled bit zero */
        if ( !sys_call_table )
        {
            sys_call_table = talpa_find_syscall_table((void **)((unsigned long)get_start_addr()^1), unique_syscalls, num_unique_syscalls, zapped_syscalls, num_zapped_syscalls, 1);
        }
        syscall_table = (unsigned long)sys_call_table;
    }

    if ( sys_call_table == NULL )
    {
        err("Cannot find syscall table!");
        return -ESRCH;
    }

    dbg("Syscall table at 0x%p", sys_call_table);
    return 0;
}
#else
static int find_syscall_table(void)
{
    return 0;
}
#endif

static void save_originals(void)
{
#ifdef CONFIG_X86
    orig_mount = sys_call_table[__NR_mount];
#else
  #error "Architecture currently not supported!"
#endif
}

static void patch_table(void)
{
    sys_call_table[__NR_mount] = talpa_mount;
}

static unsigned int check_table(void)
{
    if ( sys_call_table[__NR_mount] != talpa_mount )
    {
        warn("mount() is patched by someone else!");
        return 1;
    }

    return 0;
}

static void restore_table(void)
{
#if defined CONFIG_X86
    sys_call_table[__NR_mount] = orig_mount;
#endif
}

/*
 * Module init and exit
 */

static int __init talpa_syscallhook_init(void)
{
    int ret;


    ret = find_syscall_table();
    if ( ret < 0 )
    {
        return ret;
    }

    lock_kernel();
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    fsync_dev(0);
#endif
    save_originals();
    talpa_syscallhook_modify_start();
    patch_table();
    talpa_syscallhook_modify_finish();
    unlock_kernel();

    dbg("Hooked [%s]", hook_mask);

    return 0;
}

static void __exit talpa_syscallhook_exit(void)
{
    lock_kernel();
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    fsync_dev(0);
#endif

    /* We have to cater for the possibility that someone else
       has modified the syscall table after us. Therefore we
       will check for that and sleep until the situation resolves.
       There isn't really a perfect solution in these sorts of
       unsupported oprations so it is better to hang here than
       to cause system instability in any way.
       The best thing would be to leave this module loaded forever.
    */
    while ( check_table() != 0 )
    {
        unlock_kernel();
        __set_current_state(TASK_UNINTERRUPTIBLE);
        schedule_timeout(HZ);
        lock_kernel();
    }
    talpa_syscallhook_modify_start();
    restore_table();
    talpa_syscallhook_modify_finish();
    unlock_kernel();

    dbg("Unhooked");
}

module_init(talpa_syscallhook_init);
module_exit(talpa_syscallhook_exit);

MODULE_DESCRIPTION("TALPA Filesystem Interceptor Test Module");
MODULE_AUTHOR("Sophos Plc");
MODULE_LICENSE("GPL");

/*
 * End of talpa_syscalltable.c
 */
