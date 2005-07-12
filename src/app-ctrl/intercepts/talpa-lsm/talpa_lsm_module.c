/*
 * talpa_lsm_module.c
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

#define TALPA_SUBSYS "lsm"
#include "common/talpa.h"
#include "components/intercepts/lsm_impl/lsm_interceptor.h"
#include "app_ctrl/iportability_app_ctrl.h"
#include "app_ctrl/icore_app_ctrl.h"


#ifdef TALPA_ID
const char talpa_id[] = "$TALPA_ID:" TALPA_ID;
#endif

static LSMInterceptor* mIntercept = NULL;


static int __init talpa_lsm_init(void)
{
    IInterceptProcessor*    target;
    IConfigurator*          config;


    /*
     * Create a new interceptor!
     */
    mIntercept = newLSMInterceptor();
    if (mIntercept == 0)
    {
        err("Failed to create interceptor!");
        return -ENOMEM;
    }

    /*
     * Set the InterceptProcessor that will be targetted by the Interceptor.
     */
    target = TALPA_Core()->interceptProcessor();
    if (target == 0)
    {
        err("Failed to obtain intercept processor!");
        mIntercept->delete(mIntercept);
        return -ENOENT;
    }
    mIntercept->i_IInterceptor.addInterceptProcessor(mIntercept, target);

    /*
     * Expose the Interceptor's configuration.
     */
    config = TALPA_Portability()->configurator();
    config->attach(config->object, ECG_Interceptor, &mIntercept->i_IConfigurable);

    dbg("Ready");
    return 0;

}

static void __exit talpa_lsm_exit(void)
{
    IConfigurator*          config;


    config = TALPA_Portability()->configurator();
    config->detach(config->object, &mIntercept->i_IConfigurable);

    if (mIntercept != 0)
    {
        mIntercept->delete(mIntercept);
    }
    dbg("Unloaded");
    return;
}

/*
 *
 * Module information.
 *
 */
MODULE_AUTHOR("Sophos Plc");
MODULE_DESCRIPTION("TALPA Filesystem Interceptor LSM Intercept Module");
MODULE_LICENSE("GPL");

module_init(talpa_lsm_init);
module_exit(talpa_lsm_exit);


/*
 * End of talpa_lsm_module.c
 */
