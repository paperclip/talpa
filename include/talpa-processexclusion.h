/*
 * talpa-processexclusion.h
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

#ifndef H_PROCESSEXCLUSION
#define H_PROCESSEXCLUSION

#ifndef __KERNEL__
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif



#ifdef __cplusplus
}
#endif


#define TLPPEIOC_ACTIVE         _IO ( 0xfe,     0 )
#define TLPPEIOC_IDLE           _IO ( 0xfe,     1 )


#endif

/*
 * End of talpa-processexclusion.h
 */
