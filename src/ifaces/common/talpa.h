/*
 * talpa.h
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
#ifndef H_TALPA
#define H_TALPA

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/autoconf.h>
#include <linux/list.h>
#include <linux/module.h>
#include <asm/param.h>


#ifdef DEBUG
#define emerg(format, arg...) printk(KERN_EMERG "TALPA [" __FILE__ " ### %s] " format "\n" , __FUNCTION__, ## arg)
#define alert(format, arg...) printk(KERN_ALERT "TALPA [" __FILE__ " ### %s] " format "\n" , __FUNCTION__, ## arg)
#define critical(format, arg...) printk(KERN_CRIT "TALPA [" __FILE__ " ### %s] " format "\n" , __FUNCTION__, ## arg)
#define err(format, arg...) printk(KERN_ERR "TALPA [" __FILE__ " ### %s] " format "\n" , __FUNCTION__, ## arg)
#define warn(format, arg...) printk(KERN_WARNING "TALPA [" __FILE__ " ### %s] " format "\n" , __FUNCTION__, ## arg)
#define notice(format, arg...) printk(KERN_NOTICE "TALPA [" __FILE__ " ### %s] " format "\n" , __FUNCTION__, ## arg)
#define info(format, arg...) printk(KERN_INFO "TALPA [" __FILE__ " ### %s] " format "\n" , __FUNCTION__, ## arg)
#define dbg(format, arg...) printk(KERN_DEBUG "TALPA [" __FILE__ " ### %s] " format "\n" , __FUNCTION__, ## arg)
#else
#ifdef TALPA_SUBSYS
#define emerg(format, arg...) printk(KERN_EMERG "talpa-" TALPA_SUBSYS ": " format "\n" , ## arg)
#define alert(format, arg...) printk(KERN_ALERT "talpa-" TALPA_SUBSYS ": " format "\n" , ## arg)
#define critical(format, arg...) printk(KERN_CRIT "talpa-" TALPA_SUBSYS ": " format "\n" , ## arg)
#define err(format, arg...) printk(KERN_ERR "talpa-" TALPA_SUBSYS ": " format "\n" , ## arg)
#define warn(format, arg...) printk(KERN_WARNING "talpa-" TALPA_SUBSYS ": " format "\n" , ## arg)
#define notice(format, arg...) printk(KERN_NOTICE "talpa-" TALPA_SUBSYS ": " format "\n" , ## arg)
#define info(format, arg...) printk(KERN_INFO "talpa-" TALPA_SUBSYS ": " format "\n" , ## arg)
#else
#define emerg(format, arg...) printk(KERN_EMERG "talpa: " format "\n" , ## arg)
#define alert(format, arg...) printk(KERN_ALERT "talpa: " format "\n" , ## arg)
#define critical(format, arg...) printk(KERN_CRIT "talpa: " format "\n" , ## arg)
#define err(format, arg...) printk(KERN_ERR "talpa: " format "\n" , ## arg)
#define warn(format, arg...) printk(KERN_WARNING "talpa: " format "\n" , ## arg)
#define notice(format, arg...) printk(KERN_NOTICE "talpa: " format "\n" , ## arg)
#define info(format, arg...) printk(KERN_INFO "talpa: " format "\n" , ## arg)
#endif
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

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)

#define __talpa_wait_event_timeout(wq, condition, timeout, ret) \
do { \
    unsigned long sleep = timeout; \
    unsigned long start, elapsed; \
    wait_queue_t __wait; \
    init_waitqueue_entry(&__wait, current); \
    ret = -ETIME; \
\
    add_wait_queue(&wq, &__wait); \
    for (;;) { \
        set_current_state(TASK_UNINTERRUPTIBLE); \
        if (condition) { \
            ret = 0; \
            break; \
        } \
        start = jiffies; \
        schedule_timeout(sleep); \
        elapsed = jiffies - start; \
        if ( elapsed >= sleep ) { \
            break; \
        } else { \
            sleep -= elapsed; \
        } \
    } \
    current->state = TASK_RUNNING; \
    remove_wait_queue(&wq, &__wait); \
} while(0)

#define talpa_wait_event_timeout(wq, condition, timeout) \
({ \
    long __ret = 0; \
    if (!(condition)) \
        __talpa_wait_event_timeout(wq, condition, timeout, __ret); \
    __ret; \
})

#define __talpa_wait_event_interruptible_timeout(wq, condition, timeout, ret) \
do { \
    unsigned long sleep = timeout; \
    unsigned long start, elapsed; \
    wait_queue_t __wait; \
    init_waitqueue_entry(&__wait, current); \
    ret = -ETIME; \
\
    add_wait_queue(&wq, &__wait); \
    for (;;) { \
        set_current_state(TASK_INTERRUPTIBLE); \
        if (condition) { \
            ret = 0; \
            break; \
        } \
        if (!signal_pending(current)) {             \
            start = jiffies; \
            schedule_timeout(sleep);                    \
            elapsed = jiffies - start; \
            if ( elapsed >= sleep ) { \
                break; \
            } else { \
                sleep -= elapsed; \
            } \
        } else { \
            ret = -ERESTARTSYS;  \
            break; \
        } \
    } \
    current->state = TASK_RUNNING; \
    remove_wait_queue(&wq, &__wait); \
} while(0)


#define talpa_wait_event_interruptible_timeout(wq, condition, timeout) \
({ \
    long __ret = 0; \
    if (!(condition)) \
        __talpa_wait_event_interruptible_timeout(wq, condition, timeout, __ret); \
    __ret; \
})

#else /* 2.4 above, 2.6 below */

#define __talpa_wait_event_timeout(wq, condition, timeout, ret) \
do { \
    unsigned long sleep = timeout; \
    unsigned long start, elapsed; \
    DEFINE_WAIT(__wait);                        \
    ret = -ETIME; \
\
    for (;;) { \
        prepare_to_wait(&wq, &__wait, TASK_UNINTERRUPTIBLE);    \
        if (condition) { \
            ret = 0; \
            break; \
        } \
        start = jiffies; \
        schedule_timeout(sleep); \
        elapsed = jiffies - start; \
        if ( elapsed >= sleep ) { \
            break; \
        } else { \
            sleep -= elapsed; \
        } \
    } \
    finish_wait(&wq, &__wait);                  \
} while(0)

#define talpa_wait_event_timeout(wq, condition, timeout) \
({ \
    long __ret = 0; \
    if (!(condition)) \
        __talpa_wait_event_timeout(wq, condition, timeout, __ret); \
    __ret; \
})

#define __talpa_wait_event_interruptible_timeout(wq, condition, timeout, ret) \
do { \
    unsigned long sleep = timeout; \
    unsigned long start, elapsed; \
    DEFINE_WAIT(__wait);                        \
    ret = -ETIME; \
\
    for (;;) { \
        prepare_to_wait(&wq, &__wait, TASK_INTERRUPTIBLE);  \
        if (condition) { \
            ret = 0; \
            break; \
        } \
        if (!signal_pending(current)) {             \
            start = jiffies; \
            schedule_timeout(sleep);                    \
            elapsed = jiffies - start; \
            if ( elapsed >= sleep ) { \
                break; \
            } else { \
                sleep -= elapsed; \
            } \
        } else { \
            ret = -ERESTARTSYS;  \
            break; \
        } \
    } \
    finish_wait(&wq, &__wait);                  \
} while(0)


#define talpa_wait_event_interruptible_timeout(wq, condition, timeout) \
({ \
    long __ret = 0; \
    if (!(condition)) \
        __talpa_wait_event_interruptible_timeout(wq, condition, timeout, __ret); \
    __ret; \
})

#endif /* Kernel version */


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0) || defined TALPA_HAS_NEW_PARENT
#define processParentPID(task) task->parent->pid
#else
#define processParentPID(task) task->p_pptr->pid
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,10) && !defined TALPA_HAS_SNPRINTF
#define snprintf(string, len, arg...) sprintf(string, ## arg)
#endif


#endif

/*
 * End of talpa.h
 */
