/*
 * iprocess_excluder.h
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
#ifndef H_IPROCESSEXCLUDER
#define H_IPROCESSEXCLUDER

#include <asm/atomic.h>
#include <linux/sched.h>

#include "common/list.h"

#include "talpa-processexclusion.h"

/*
 * Internal structures
 */

typedef struct
{
    talpa_list_head head;
    atomic_t        refcnt;
    pid_t           processID;
    pid_t           threadID;
    bool            active;
    void*           private;
} ProcessExcluded;


/*
 * IProcessExcluder
 */

typedef struct
{
    ProcessExcluded* (*registerProcess)   (void* self, pid_t pid, pid_t tid);
    void             (*deregisterProcess) (void* self, ProcessExcluded* obj);
    ProcessExcluded* (*active)            (void* self, ProcessExcluded* obj);
    ProcessExcluded* (*idle)              (void* self, ProcessExcluded* obj);
    /*
     *  Object supporting this interface instance.
     */
    void*           object;
    void            (*delete)           (void* self);
} IProcessExcluder;

#endif

/*
 * End of iprocess_excluder.h
 */

