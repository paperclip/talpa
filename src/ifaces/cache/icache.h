/*
 * icache.h
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
#ifndef H_ICACHE
#define H_ICACHE

#include "common/bool.h"

typedef struct
{
    int     (*find)     (const void* self, const uint32_t keyH, const uint32_t keyL);
    void    (*add)      (void *self, const char* class, const uint32_t keyH, const uint32_t keyL);
    void    (*clear)    (void *self, const uint32_t keyH, const uint32_t keyL);
    void    (*purge)    (void *self, const uint32_t keyH);

    bool    (*enable)   (void* self);
    void    (*disable)  (void* self);
    bool    (*isEnabled)(const void* self);

    /*
     *  Object supporting this interface instance.
     */
    void*   object;
    void    (*delete)   (void* self);
} ICache;

#endif

/*
 * End of icache.h
 */

