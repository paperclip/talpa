/*
 * talpa_syscallhookprobe.c
 *
 * TALPA Filesystem Interceptor
 *
 * Copyright(C) 2008 Sophos Plc, Oxford, England.
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

#include "platforms/linux/talpa_syscallhook.h"

#ifdef TALPA_ID
const char talpa_id[] = "$TALPA_ID:" TALPA_ID;
#endif

#ifdef TALPA_VERSION
const char talpa_version[] = "$TALPA_VERSION:" TALPA_VERSION;
#endif

/*
 * Module init and exit
 */
static int __init talpa_syscallhookprobe_init(void)
{
    return talpa_syscallhook_can_unload();
}

static void __exit talpa_syscallhookprobe_exit(void)
{

}

module_init(talpa_syscallhookprobe_init);
module_exit(talpa_syscallhookprobe_exit);

MODULE_DESCRIPTION("Load successfully if talpa_syscallhook can be unloaded.");
MODULE_AUTHOR("Sophos Plc");
MODULE_LICENSE("GPL");
#if defined TALPA_VERSION && defined MODULE_VERSION
MODULE_VERSION(TALPA_VERSION);
#endif

/*
 * End of talpa_syscallhookprobe.c
 */
