/*
 * alloc.h
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
#ifndef H_ALLOC
#define H_ALLOC

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/autoconf.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/string.h>


#if __GNUC__ == 2 && __GNUC_MINOR__ < 96
#define __builtin_expect(x, expected_value) (x)
#endif

#ifndef likely
#define likely(x)       __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x)     __builtin_expect(!!(x), 0)
#endif

static inline void *talpa_alloc(size_t bytes)
{
    return kmalloc(bytes, GFP_KERNEL);
}

static inline void *talpa_zalloc(size_t bytes)
{
    void *ptr;

    ptr =  kmalloc(bytes, GFP_KERNEL);

    if ( likely( ptr != NULL ) )
    {
        memset(ptr, 0, bytes);
    }

    return ptr;
}

static inline void talpa_free(void *ptr)
{
    kfree(ptr);
}

static inline void *talpa_large_alloc(size_t bytes)
{
    return vmalloc(bytes);
}

static inline void talpa_large_free(void *ptr)
{
    vfree(ptr);
}

static inline char *talpa_alloc_path(size_t *size)
{
    unsigned int order = 4;
    char *buf;
    size_t bufsize;

    do
    {
        bufsize = PAGE_SIZE << order;
        buf = kmalloc(bufsize, GFP_KERNEL);
        order--;
    } while ( !buf && (order > 0) );

    if ( buf && size )
    {
        *size = bufsize;
    }

    return buf;
}

static inline void talpa_free_path(char *buf)
{
    kfree(buf);
}

#endif
/*
 * End of alloc.h
 */
