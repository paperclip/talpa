/*
 * linux_waitq.h
 *
 * TALPA Filesystem Interceptor
 *
 * Copyright (C) 2004-2011 Sophos Limited, Oxford, England.
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
#ifndef H_LINUXWAITQ
#define H_LINUXWAITQ

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <asm/atomic.h>


#define time_diff(start, end) \
({ \
    unsigned long diff; \
\
    if ( end >= start ) { \
        diff = end - start; \
    } else { \
        diff = end + (~0UL - start); \
    } \
\
    diff; \
})

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
        elapsed = time_diff(start, jiffies); \
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

#define talpa_wait_event_killable_timeout talpa_wait_event_timeout

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
            elapsed = time_diff(start, jiffies); \
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

#define __talpa_wait_event_interruptible_exclusive(wq, condition, ret) \
do { \
        wait_queue_t __wait; \
        init_waitqueue_entry(&__wait, current); \
\
        add_wait_queue_exclusive(&wq, &__wait); \
        for (;;) { \
                set_current_state(TASK_INTERRUPTIBLE); \
                if (condition) \
                        break; \
                if (!signal_pending(current)) { \
                        schedule(); \
                        continue; \
                } \
                ret = -ERESTARTSYS; \
                break; \
        } \
        current->state = TASK_RUNNING; \
        remove_wait_queue(&wq, &__wait); \
} while (0)

#define talpa_wait_event_interruptible_exclusive(wq, condition) \
({ \
    long __ret = 0; \
    if (!(condition)) \
        __talpa_wait_event_interruptible_exclusive(wq, condition, __ret); \
    __ret; \
})

#define __talpa_wait_event_interruptible_exclusive_timeout(wq, condition, timeout, ret) \
do { \
    unsigned long sleep = timeout; \
    unsigned long start, elapsed; \
    wait_queue_t __wait; \
    init_waitqueue_entry(&__wait, current); \
    ret = -ETIME; \
\
    add_wait_queue_exclusive(&wq, &__wait); \
    for (;;) { \
        set_current_state(TASK_INTERRUPTIBLE); \
        if (condition) { \
            ret = 0; \
            break; \
        } \
        if (!signal_pending(current)) {             \
            start = jiffies; \
            schedule_timeout(sleep);                    \
            elapsed = time_diff(start, jiffies); \
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

#define talpa_wait_event_interruptible_exclusive_timeout(wq, condition, timeout) \
({ \
    long __ret = 0; \
    if (!(condition)) \
        __talpa_wait_event_interruptible_exclusive_timeout(wq, condition, timeout, __ret); \
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
        elapsed = time_diff(start, jiffies); \
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
            elapsed = time_diff(start, jiffies); \
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

#ifdef TASK_KILLABLE
#define __talpa_wait_event_killable_timeout(wq, condition, timeout, ret) \
do { \
    unsigned long sleep = timeout; \
    unsigned long start, elapsed; \
    DEFINE_WAIT(__wait);                        \
    ret = -ETIME; \
\
    for (;;) { \
        prepare_to_wait(&wq, &__wait, TASK_KILLABLE);  \
        if (condition) { \
            ret = 0; \
            break; \
        } \
        if (!fatal_signal_pending(current)) {             \
            start = jiffies; \
            schedule_timeout(sleep);                    \
            elapsed = time_diff(start, jiffies); \
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


#define talpa_wait_event_killable_timeout(wq, condition, timeout) \
({ \
    long __ret = 0; \
    if (!(condition)) \
        __talpa_wait_event_killable_timeout(wq, condition, timeout, __ret); \
    __ret; \
})
#else /* !TASK_KILLABLE */
#define talpa_wait_event_killable_timeout talpa_wait_event_timeout
#endif /* TASK_KILLABLE */

#define __talpa_wait_event_interruptible_exclusive(wq, condition, ret) \
do { \
    DEFINE_WAIT(__wait); \
\
    for (;;) { \
        prepare_to_wait_exclusive(&wq, &__wait, TASK_INTERRUPTIBLE); \
        if (condition) \
            break; \
        if (!signal_pending(current)) { \
            schedule(); \
        } else { \
            ret = -ERESTARTSYS; \
            break; \
        } \
    } \
    finish_wait(&wq, &__wait); \
} while(0)

#define talpa_wait_event_interruptible_exclusive(wq, condition) \
({ \
    long __ret = 0; \
    if (!(condition)) \
        __talpa_wait_event_interruptible_exclusive(wq, condition, __ret); \
    __ret; \
})

#define __talpa_wait_event_interruptible_exclusive_timeout(wq, condition, timeout, ret) \
do { \
    unsigned long sleep = timeout; \
    unsigned long start, elapsed; \
    DEFINE_WAIT(__wait);                        \
    ret = -ETIME; \
\
    for (;;) { \
        prepare_to_wait_exclusive(&wq, &__wait, TASK_INTERRUPTIBLE);  \
        if (condition) { \
            ret = 0; \
            break; \
        } \
        if (!signal_pending(current)) {             \
            start = jiffies; \
            schedule_timeout(sleep);                    \
            elapsed = time_diff(start, jiffies); \
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

#define talpa_wait_event_interruptible_exclusive_timeout(wq, condition, timeout) \
({ \
    long __ret = 0; \
    if (!(condition)) \
        __talpa_wait_event_interruptible_exclusive_timeout(wq, condition, timeout, __ret); \
    __ret; \
})

#endif /* Kernel version */


/* Emulate completion on old 2.4 kernels */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,6)

struct talpa_completion
{
    atomic_t            complete;
    wait_queue_head_t   wait;
};

static inline void talpa_init_completion(struct talpa_completion *c)
{
    atomic_set(&c->complete, 0);
    init_waitqueue_head(&c->wait);
}

static inline void talpa_wait_for_completion(struct talpa_completion *c)
{
    wait_event(c->wait, atomic_read(&c->complete));
    atomic_set(&c->complete, 0);
}

static inline void talpa_complete(struct talpa_completion *c)
{
    atomic_set(&c->complete, 1);
    wake_up(&c->wait);
}

#else

#include <linux/completion.h>

#define talpa_completion            completion
#define talpa_init_completion       init_completion

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11)
#define talpa_wait_for_completion   wait_for_completion
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
#define talpa_wait_for_completion           wait_for_completion_interruptible
#define talpa_wait_for_completion_timeout   wait_for_completion_interruptible_timeout
#else
#define talpa_wait_for_completion           wait_for_completion_killable
#define talpa_wait_for_completion_timeout   wait_for_completion_killable_timeout
#endif

#define talpa_complete              complete

#endif /* < 2.4.6 (completion) */


#endif

/*
 * End of linuxwaitq.h
 */
