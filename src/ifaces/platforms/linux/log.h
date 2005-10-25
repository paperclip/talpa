/*
 * linux_log.h
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
#ifndef H_LINUXLOG
#define H_LINUXLOG

#include <linux/kernel.h>

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

#endif

/*
 * End of linux_log.h
 */
