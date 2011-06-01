/*
 * pod_configuration_element.h
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
#ifndef H_PODCONIFGURATIONELEMENT
#define H_PODCONIFGURATIONELEMENT

#include "common/bool.h"

typedef struct
{
    char*   name;
    char*   value;
    int     maxvalue_sz;
    bool    writable;
    bool    world_readable;
} PODConfigurationElement;

#endif

/*
 * End of pod_configuration_element.h
 */

