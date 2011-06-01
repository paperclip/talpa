/*
 * iconfigurable.h
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
#ifndef H_ICONFIGURABLE
#define H_ICONFIGURABLE

#include "pod_configuration_element.h"

typedef struct
{
    const char*                    (*name)(const void* self);
    const PODConfigurationElement* (*all) (const void* self);
    const char*                    (*get) (const void* self, const char* name);
    void                           (*set) (void* self, const char* name, const char* value);
    /*
     *  Object supporting this interface instance.
     */
    void*                          object;
    void                           (*delete) (void* self);
} IConfigurable;

#endif

/*
 * End of iconfigurable.h
 */

