/*
 * linux_locking.h
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
#ifndef H_LINUXLOCKING
#define H_LINUXLOCKING

#include <linux/kernel.h>
#include <linux/autoconf.h>
#include <linux/spinlock.h>
#include <asm/semaphore.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#include <linux/rcupdate.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,4)
#include <linux/rwsem.h>
#endif

typedef spinlock_t talpa_simple_lock_t;

#define TALPA_SIMPLE_UNLOCKED   SPIN_LOCK_UNLOCKED
#define talpa_simple_init       spin_lock_init
#define talpa_simple_lock       spin_lock
#define talpa_simple_unlock     spin_unlock

typedef rwlock_t talpa_rw_lock_t;

#define TALPA_RW_UNLOCKED   RW_LOCK_UNLOCKED
#define talpa_rw_init       rwlock_init
#define talpa_read_lock     read_lock
#define talpa_read_unlock   read_unlock
#define talpa_write_lock    write_lock
#define talpa_write_unlock  write_unlock

typedef struct semaphore talpa_mutex_t;

#define TALPA_MUTEX_INIT        { }
#define TALPA_STATIC_MUTEX(x)   __MUTEX_INITIALIZER(x)
#define talpa_mutex_init        init_MUTEX
#define talpa_mutex_lock        down
#define talpa_mutex_unlock      up

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)

typedef spinlock_t talpa_rcu_lock_t;

#define TALPA_RCU_UNLOCKED          SPIN_LOCK_UNLOCKED
#define talpa_rcu_lock_init         spin_lock_init
#define talpa_rcu_read_lock(l)      rcu_read_lock()
#define talpa_rcu_read_unlock(l)    rcu_read_unlock()
#define talpa_rcu_write_lock(l)     spin_lock(l)
#define talpa_rcu_write_unlock(l)   spin_unlock(l)

#else /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0) */

typedef rwlock_t talpa_rcu_lock_t;

#define TALPA_RCU_UNLOCKED      RW_LOCK_UNLOCKED
#define talpa_rcu_lock_init     rwlock_init
#define talpa_rcu_read_lock     read_lock
#define talpa_rcu_read_unlock   read_unlock
#define talpa_rcu_write_lock    write_lock
#define talpa_rcu_write_unlock  write_unlock

#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0) */

#endif

/*
 * End of linux_locking.h
 */
