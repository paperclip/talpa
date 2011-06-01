/*
 * talpa_pedconnector.c
 *
 * TALPA Filesystem Interceptor
 *
 * Copyright(C) 2004-2011 Sophos Limited, Oxford, England.
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

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>

#include "common/talpa.h"
#include "components/filter-iface/process-exclusion/device_driver_pe_impl/device_driver_process_exclusion.h"


#ifdef TALPA_ID
const char talpa_id[] = "$TALPA_ID:" TALPA_ID;
#endif

#ifdef TALPA_VERSION
const char talpa_version[] = "$TALPA_VERSION:" TALPA_VERSION;
#endif

/*
 * Module init and exit
 */

static int __init talpa_pedconnector_init(void)
{
    talpa_pedevice_attach();

    return 0;
}

static void __exit talpa_pedconnector_exit(void)
{
    talpa_pedevice_detach();
}

module_init(talpa_pedconnector_init);
module_exit(talpa_pedconnector_exit);

MODULE_DESCRIPTION("Establishes connection between talpa_pedevice and talpa_core/talpa_linux modules.");
MODULE_AUTHOR("Sophos Limited");
MODULE_LICENSE("GPL");
#if defined TALPA_VERSION && defined MODULE_VERSION
MODULE_VERSION(TALPA_VERSION);
#endif


/*
 * End of talpa_pedconnector.c
 */

