/*
 * assert.h
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
#ifndef H_ASSERT
#define H_ASSERT


#ifdef ASSERT

#include "platform/log.h"

#ifdef DEBUG
#define assert(cond, format, args...) \
{ \
    if ( !(cond) ) \
    { \
        critical("assertion " #cond " failed at line %i: " format, __LINE__, ##args); \
    } \
}
#else /* DEBUG */
#include "platform/compiler.h"
#include "platform/glue.h"

#define assert(cond, format, args...) \
{ \
    if ( unlikely( !(cond) ) ) \
    { \
        critical("assertion " #cond " failed at " __FILE__ ":%s@%i: " format, __FUNCTION__, __LINE__, ##args); \
    } \
}
#endif /* DEBUG*/

#else /* ASSERT */

#define assert(cond, format, args...) {;}

#endif /* ASSERT */



#endif

/*
 * End of assert.h
 */
