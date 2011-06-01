/*
 * eintercept_action.h
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
#ifndef H_EINTERCEPTACTION
#define H_EINTERCEPTACTION

typedef enum
{
    EIA_Restart = 1,
    EIA_Next,
    EIA_Allow,
    EIA_Deny,
    EIA_Timeout,
    EIA_Error
} EInterceptAction;

#endif

/*
 * End of eintercept_action.h
 */

