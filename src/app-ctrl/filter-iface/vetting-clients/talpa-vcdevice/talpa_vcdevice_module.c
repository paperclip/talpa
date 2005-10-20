/*
 * talpa_vcdevice_module.c
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

#define TALPA_SUBSYS "vcdevice"
#include "common/talpa.h"
#include "components/filter-iface/vetting-clients/device_driver_vc_impl/device_driver_vetting_client.h"
#include "app_ctrl/iportability_app_ctrl.h"
#include "app_ctrl/icore_app_ctrl.h"


#ifdef TALPA_ID
const char talpa_id[] = "$TALPA_ID:" TALPA_ID;
#endif

static DeviceDriverVettingClient*   mClient;


static int __init talpa_vcdevice_init(void)
{
    IConfigurator* config;


    /* Create a new client */
    mClient = newDeviceDriverVettingClient(TALPA_Core()->vettingServer());
    if ( !mClient )
    {
        err("Failed to create client!");
        return -ENOMEM;
    }

    /* Expose the configuration */
    config = TALPA_Portability()->configurator();
    config->attach(config->object, ECG_FilterInterfaces, &mClient->i_IConfigurable);

    dbg("Ready");
    return 0;
}

static void __exit talpa_vcdevice_exit(void)
{
    IConfigurator* config;


    config = TALPA_Portability()->configurator();
    config->detach(config->object, &mClient->i_IConfigurable);

    mClient->delete(mClient);

    dbg("Unloaded");
    return;
}

/*
 *
 * Module information.
 *
 */
MODULE_AUTHOR("Sophos Plc");
MODULE_DESCRIPTION("TALPA Filesystem Interceptor Device Driver Vetting Client Module");
MODULE_LICENSE("GPL");

module_init(talpa_vcdevice_init);
module_exit(talpa_vcdevice_exit);


/*
 * End of talpa_vcdevice_module.c
 */
