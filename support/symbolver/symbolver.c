/*
 * stacker.c
 *
 * TALPA Filesystem Interceptor
 *
 * Copyright(C) 2004-2011 Sophos Limited, Oxford, England.
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
#include <linux/rcupdate.h>
#include <linux/wait.h>
#include <linux/security.h>



#ifdef TALPA_ID
const char talpa_id[] = "$TALPA_ID:" TALPA_ID;
#endif

#ifdef TALPA_VERSION
const char talpa_version[] = "$TALPA_VERSION:" TALPA_VERSION;
#endif

#define err(format, arg...) printk(KERN_ERR "symbolver: " format "\n" , ## arg)
#define warn(format, arg...) printk(KERN_WARNING "symbolver: " format "\n" , ## arg)
#define notice(format, arg...) printk(KERN_NOTICE "symbolver: " format "\n" , ## arg)
#define info(format, arg...) printk(KERN_INFO "symbolver: " format "\n" , ## arg)

/*
 * Relocatable hidden kernel symbol support.
 */
#ifndef CONFIG_RELOCATABLE
static __inline const void* talpa_get_symbol(const char* name, const void* ptr)
{
    (void)name;


    return ptr;
}
#else
static __inline const void* talpa_get_symbol(const char* name, const void* ptr)
{
    long offset = (unsigned long)&printk - TALPA_PRINTK_ADDR;


    (void)name;

    return (void *)ptr + offset;
}
#endif

static int __init symbolver_init(void)
{
    long offset = (unsigned long)&printk - TALPA_PRINTK_ADDR;

    err("Symbol verifier init");
#ifdef CONFIG_RELOCATABLE
    err("CONFIG_RELOCATABLE");
#else
    err("not CONFIG_RELOCATABLE");
    if (offset != 0)
    {
        err("ERROR: not CONFIG_RELOCATABLE and offset not zero: is %lx",offset);
    }
#endif
    err("CONFIG PRINTK %x",TALPA_PRINTK_ADDR);
    err("ADDR %lx",(unsigned long)&printk);
    err("DIFF %lx",(unsigned long)offset);

    err("kstrdup %lx", (unsigned long)&kstrdup);

    err("jiffies %lx",(unsigned long)&jiffies);


    err("Finish init");

    return 0;
}

static void __exit symbolver_exit(void)
{
}


module_init (symbolver_init);
module_exit (symbolver_exit);

MODULE_DESCRIPTION("Print out symbol addresses for verification.");
MODULE_AUTHOR("Sophos Limited");
MODULE_LICENSE("GPL");
#if defined TALPA_VERSION && defined MODULE_VERSION
MODULE_VERSION(TALPA_VERSION);
#endif


/*
 * End of stacker.c
 */

