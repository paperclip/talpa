/*
 * talpa_pedevice_module.c
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

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>

#include <asm/errno.h>

#define TALPA_SUBSYS "pedevice"
#include "common/talpa.h"
#include "components/filter-iface/process-exclusion/device_driver_pe_impl/device_driver_process_exclusion.h"


#ifdef TALPA_ID
const char talpa_id[] = "$TALPA_ID:" TALPA_ID;
#endif

static DeviceDriverProcessExclusion*   mProcExcl;

static int __init talpa_pedevice_init(void)
{
    /* Create a new client */
    mProcExcl = newDeviceDriverProcessExclusion();
    if ( !mProcExcl )
    {
        err("Failed to create process excluder!");
        return -ENOMEM;
    }

    if ( !mProcExcl->attach(mProcExcl) )
    {
        dbg("Staying in detached mode");
    }

    return 0;
}

static void __exit talpa_pedevice_exit(void)
{
    mProcExcl->delete(mProcExcl);

    dbg("Unloaded");
    return;
}

/*
 *
 * Module information.
 *
 */
MODULE_AUTHOR("Sophos Plc");
MODULE_DESCRIPTION("TALPA Filesystem Interceptor Device Driver Process Exclusion Module");
MODULE_LICENSE("GPL");

module_init(talpa_pedevice_init);
module_exit(talpa_pedevice_exit);


/*
 * End of talpa_pedevice_module.c
 */
