/*
 * linux_processandthread_factoryimpl.c
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
#include "linux_processandthread_factoryimpl.h"
#include "linux_threadinfo.h"

/*
 * Forward declare implementation methods.
 */
static IThreadInfo* newThreadInfo(const void* self);
static void deleteLinuxThreadAndProcessFactoryImpl(struct tag_LinuxThreadAndProcessFactoryImpl* object);

/*
 * Singleton object.
 */
static LinuxThreadAndProcessFactoryImpl GL_object =
    {
        {
            newThreadInfo,
            &GL_object,
            (void (*)(const void*))deleteLinuxThreadAndProcessFactoryImpl
        },
        deleteLinuxThreadAndProcessFactoryImpl,
    };


/*
 * Object creation/destruction.
 */
LinuxThreadAndProcessFactoryImpl* newLinuxThreadAndProcessFactoryImpl(void)
{
    return &GL_object;
}

static void deleteLinuxThreadAndProcessFactoryImpl(struct tag_LinuxThreadAndProcessFactoryImpl* object)
{
    return;
}


/*
 * IProcessAndThreadFactory.
 */
static IThreadInfo* newThreadInfo(const void* self)
{
    LinuxThreadInfo*  object;


    object = newLinuxThreadInfo();
    return (object != NULL) ? &object->i_IThreadInfo : NULL;
}

/*
 * End of linux_processandthread_factoryimpl.c
 */
