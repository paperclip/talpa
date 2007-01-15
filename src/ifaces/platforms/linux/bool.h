/*
 * linux_bool.h
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
#ifndef H_LINUXBOOL
#define H_LINUXBOOL

#include <linux/version.h>
#include <linux/types.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
typedef int bool;
#endif

#ifndef true
#define true    (1==1)
#endif

#ifndef false
#define false   (1==0)
#endif

#endif

/*
 * End of linux_bool.h
 */
