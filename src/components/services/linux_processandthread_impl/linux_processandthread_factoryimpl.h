/*
 * linux_processandthread_factoryimpl.h
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
#ifndef H_LINUXPROCESSANDTHREADFACTORYIMPL
#define H_LINUXPROCESSANDTHREADFACTORYIMPL

#include "process_and_thread/ithreadandprocess_factory.h"


typedef struct tag_LinuxThreadAndProcessFactoryImpl
{
    IThreadAndProcessFactory    i_IThreadAndProcessFactory;
    void                        (*delete)(struct tag_LinuxThreadAndProcessFactoryImpl* object);
} LinuxThreadAndProcessFactoryImpl;

/*
 * Object Creators.
 */
LinuxThreadAndProcessFactoryImpl* newLinuxThreadAndProcessFactoryImpl(void);


#endif

/*
 * End of linux_processandthread_factoryimpl.h
 */

