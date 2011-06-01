/*
 * iinterceptor.h
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
#ifndef H_IINTERCEPTOR
#define H_IINTERCEPTOR

#include "common/bool.h"
#include "intercept_processing/iintercept_processor.h"

typedef struct
{
    bool                 (*enable)               (void* self);
    void                 (*disable)              (void* self);
    bool                 (*isEnabled)            (const void* self);
    void                 (*addInterceptProcessor)(void* self, IInterceptProcessor* processor);
    IInterceptProcessor* (*interceptProcessor)   (const void* self);
    /*
     *  Object supporting this interface instance.
     */
    void* object;
    void  (*delete)                (void* self);
} IInterceptor;

#endif

/*
 * End of iinterceptor.h
 */

