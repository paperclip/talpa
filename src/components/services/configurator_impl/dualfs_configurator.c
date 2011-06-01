/*
 * dualfs_configurator.h
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
#include <linux/kernel.h>
#include <linux/version.h>

#include "common/bool.h"
#define TALPA_SUBSYS "dualfs"
#include "common/talpa.h"
#include "common/list.h"
#include "platform/alloc.h"
#include "configurator/pod_configuration_element.h"

#include "dualfs_configurator.h"

/*
 * Forward declare implementation methods.
 */
static int attach(void* self, EConfigurationGroup group, const IConfigurable* item);
static void detach(void* self, const IConfigurable* item);
static void deleteDualfsConfigurator(struct tag_DualfsConfigurator* object);

/*
 * Singleton object.
 */
static DualfsConfigurator GL_object =
    {
        {
            attach,
            detach,
            &GL_object,
            (void (*)(void*))deleteDualfsConfigurator
        },
        deleteDualfsConfigurator,
        NULL,
        NULL,
    };


#define this    ((DualfsConfigurator*)self)

/*
 * Object creation/destruction.
 */
DualfsConfigurator* newDualfsConfigurator(bool noprocfs)
{
    if ( !noprocfs )
    {
        GL_object.mProcFS = newProcfsConfigurator();
        if ( !GL_object.mProcFS )
        {
            info("Failed to create procfs configurator!");
            return NULL;
        }
    }

    GL_object.mSecurityFS = newSecurityfsConfigurator();
    if ( !GL_object.mSecurityFS )
    {
        if ( GL_object.mProcFS )
        {
            GL_object.mProcFS->delete(GL_object.mProcFS);
        }
        info("Failed to create securityfs configurator!");
        return NULL;
    }

    return &GL_object;
}

static void deleteDualfsConfigurator(struct tag_DualfsConfigurator* object)
{
    if ( object->mProcFS )
    {
        object->mProcFS->delete(object->mProcFS);
    }
    object->mSecurityFS->delete(object->mSecurityFS);
    return;
}

/*
 * IConfigurator.
 */
static int attach(void* self, EConfigurationGroup id, const IConfigurable* item)
{
    int err = 0;


    if ( this->mProcFS )
    {
        err = this->mProcFS->i_IConfigurator.attach(this->mProcFS, id, item);
        if ( err )
        {
            return err;
        }
    }

    err = this->mSecurityFS->i_IConfigurator.attach(this->mSecurityFS, id, item);
    if ( err )
    {
        if ( this->mProcFS )
        {
            this->mProcFS->i_IConfigurator.detach(this->mProcFS, item);
        }
    }

    return err;
}

static void detach(void* self, const IConfigurable* item)
{
    if ( this->mProcFS )
    {
        this->mProcFS->i_IConfigurator.detach(this->mProcFS, item);
    }
    this->mSecurityFS->i_IConfigurator.detach(this->mSecurityFS, item);
}

/*
 * End of dualfs_configurator.c
 */
