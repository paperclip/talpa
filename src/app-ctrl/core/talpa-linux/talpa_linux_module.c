/*
 * talpa_linux_module.c
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

/*
 * Standard headers for LKMs
 */
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <asm/page.h>
#include <linux/dcache.h>
#include <linux/sched.h>

#include <asm/errno.h>


#define TALPA_SUBSYS "linux"
#include "common/talpa.h"
#include "components/services/configurator_impl/procfs_configurator.h"
#include "components/services/linux_filesystem_impl/linux_systemroot.h"
#include "components/services/linux_filesystem_impl/linux_filesystem_factoryimpl.h"
#include "components/services/linux_personality_impl/linux_personality_factoryimpl.h"
#include "components/services/linux_processandthread_impl/linux_processandthread_factoryimpl.h"

#include "app_ctrl/iportability_app_ctrl.h"

/*
 * Forward declarations.
 */
static IConfigurator*               configurator(void);
static ISystemRoot*                 systemRoot(void);
static IFilesystemFactory*          filesystemFactory(void);
static IPersonalityFactory*         personalityFactory(void);
static IThreadAndProcessFactory*    threadandprocessFactory(void);


static ProcfsConfigurator* mConfig;
static LinuxSystemRoot* mSystemRoot;

/*
 * Singleton Object.
 */
static IPortabilityApplicationControl GL_talpa_linux =
    {
        configurator,
        systemRoot,
        filesystemFactory,
        personalityFactory,
        threadandprocessFactory
    };

#ifdef TALPA_ID
const char talpa_id[] = "$TALPA_ID:" TALPA_ID;
#endif

const IPortabilityApplicationControl* TALPA_Portability(void)
{
    return &GL_talpa_linux;
}

static IConfigurator* configurator(void)
{
    return &mConfig->i_IConfigurator;
}

static ISystemRoot* systemRoot(void)
{
    return &mSystemRoot->i_ISystemRoot;
}

static IFilesystemFactory* filesystemFactory(void)
{
    return &(newLinuxFilesystemFactoryImpl()->i_IFilesystemFactory);
}

static IPersonalityFactory* personalityFactory(void)
{
    return &(newLinuxPersonalityFactoryImpl()->i_IPersonalityFactory);
}

static IThreadAndProcessFactory* threadandprocessFactory(void)
{
    return &(newLinuxThreadAndProcessFactoryImpl()->i_IThreadAndProcessFactory);
}

static int __init talpa_linux_init(void)
{
    /*
     * Create the procfs configurator.
     */

    mConfig = newProcfsConfigurator();

    if ( !mConfig )
    {
        err("Failed to create configurator!");
        return -ENOMEM;
    }

    mSystemRoot = newLinuxSystemRoot();

    if ( !mSystemRoot )
    {
        err("Failed to create system root!");
        mConfig->delete(mConfig);
        return -ENOMEM;
    }

    /*
     * Register for intermodule communication on 2.4 kernels.
     */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    inter_module_register("TALPA_Portability", THIS_MODULE, (const void *)TALPA_Portability);
#endif

    dbg("Ready");

    return 0;
}

static void __exit talpa_linux_exit(void)
{
    /*
     * Unregister intermodule communication on 2.4 kernels.
     */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    inter_module_unregister("TALPA_Portability");
#endif

    mSystemRoot->delete(mSystemRoot);
    mConfig->delete(mConfig);

    dbg("Unloaded");

    return;
}

/*
 *
 * Module information.
 *
 */
MODULE_AUTHOR("Sophos Plc");
MODULE_DESCRIPTION("TALPA Filesystem Interceptor Linux Platform Module");
MODULE_LICENSE("GPL");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
EXPORT_SYMBOL(TALPA_Portability);
#else
EXPORT_SYMBOL_NOVERS(TALPA_Portability);
#endif

module_init(talpa_linux_init);
module_exit(talpa_linux_exit);


/*
 * End of talpa_linux_module.c
 */
