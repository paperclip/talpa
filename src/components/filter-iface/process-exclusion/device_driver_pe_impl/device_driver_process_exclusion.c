/*
 * device_driver_process_exclusion.c
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

#define __NO_VERSION__
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/poll.h>
#include <linux/major.h>
#include <linux/miscdevice.h>

#define TALPA_SUBSYS "pedevice"
#include "common/talpa.h"
#include "app_ctrl/icore_app_ctrl.h"
#include "app_ctrl/iportability_app_ctrl.h"
#include "device_driver_process_exclusion.h"

/*
 * Forward declare implementation methods.
 */
static int ddpeOpen(struct inode* inode, struct file* file);
static int ddpeClose(struct inode* inode, struct file* file);
static int ddpeIoctl(struct inode* inode, struct file* file, unsigned int cmd, unsigned long arg);

static bool attach(void* self);
static bool detach(void* self);

static const char* configName(const void* self);
static const PODConfigurationElement* allConfig(const void* self);
static const char* config(const void* self, const char* name);
static void setConfig(void* self, const char* name, const char* value);
static void deleteDeviceDriverProcessExclusion(struct tag_DeviceDriverProcessExclusion* object);

/*
 * Constants
 */

#define DDPE_NAME   "process-exclusion"
#define DDPE_MINOR  MISC_DYNAMIC_MINOR

#define CFG_DEVICE          "device"
#define CFG_LOCATION        "deviceName"

#define CFG_VALUE_DEVICE    "000,000"
#define CFG_VALUE_DUMMY     "(empty)"

/*
 * Singleton object
 */
static DeviceDriverProcessExclusion GL_object =
    {
        {
            ddpeOpen,
            ddpeClose,
            NULL,
            NULL,
            ddpeIoctl,
            NULL,
            &GL_object,
            (void (*)(void*))deleteDeviceDriverProcessExclusion
        },
        {
            configName,
            allConfig,
            config,
            setConfig,
            &GL_object,
            (void (*)(void*))deleteDeviceDriverProcessExclusion
        },
        deleteDeviceDriverProcessExclusion,
        attach,
        detach,
        { },
        NULL,
        { },
        NULL,
        false, /* mAttached */
        {
            {GL_object.mDeviceConfigData[0].name, GL_object.mDeviceConfigData[0].value, DDPE_CFGDATASIZE, false, true },
            {GL_object.mLocationConfigData[0].name, GL_object.mLocationConfigData[0].value, DDPE_CFGLOCATIONSIZE, true, true },
            {0, 0, 0, false, false },
        },
        {
            { CFG_DEVICE, CFG_VALUE_DEVICE }
        },
        {
            { CFG_LOCATION, CFG_VALUE_DUMMY }
        }
    };
#define this    ((DeviceDriverProcessExclusion*)self)

/*
 * DeviceDriver interface
 */
static struct file_operations ddpe_fops =
{
    owner:      THIS_MODULE,
    open:       ddpeOpen,
    release:    ddpeClose,
    ioctl:      ddpeIoctl,
};

static struct miscdevice ddpe_dev =
{
    DDPE_MINOR,
    DDPE_NAME,
    &ddpe_fops
};

/*
 * Object creation/destruction.
 */
DeviceDriverProcessExclusion* newDeviceDriverProcessExclusion(void)
{
    int ret;

    ret = misc_register(&ddpe_dev);

    if ( ret )
    {
        err("Failed to register misc device!");
        return NULL;
    }

    sprintf(GL_object.mDeviceConfigData[0].value, "%d,%d", MISC_MAJOR, ddpe_dev.minor);

    init_rwsem(&GL_object.mSem);
    TALPA_INIT_LIST_HEAD(&GL_object.mContextList);

    return &GL_object;
}

static void deleteDeviceDriverProcessExclusion(struct tag_DeviceDriverProcessExclusion* object)
{
    struct DDPEOpenContext* ctx;
    struct DDPEOpenContext* tmp;
    int ret;

    ret = misc_deregister(&ddpe_dev);

    if ( ret )
    {
        err("Failed to unregister character device in destructor!");
    }

    GL_object.detach(&GL_object);

    down_write(&GL_object.mSem);
    talpa_list_for_each_entry_safe(ctx, tmp, &GL_object.mContextList, head)
    {
        dbg("freeing context 0x%p", ctx);
        kfree(ctx);
    }
    up_write(&GL_object.mSem);

    return;
}

/*
 * IDeviceFile
 */

static int ddpeOpen(struct inode* inode, struct file* file)
{
    IProcessExcluder* procexcl;
    struct DDPEOpenContext* ctx;


    ctx = kmalloc(sizeof(struct DDPEOpenContext), GFP_KERNEL);
    if ( !ctx )
    {
        return -ENOMEM;
    }

    down_write(&GL_object.mSem);

    procexcl = GL_object.mProcExcl;
    if ( !procexcl )
    {
        up_write(&GL_object.mSem);
        kfree(ctx);
        return -ENODEV;
    }

    ctx->modified = false;
    ctx->state = false;
    ctx->closed = false;
    ctx->excluded = procexcl->registerProcess(procexcl->object);

    if ( !ctx->excluded )
    {
        up_write(&GL_object.mSem);
        kfree(ctx);
        return -ENOMEM;
    }

    file->private_data = ctx;

    talpa_list_add_tail(&ctx->head, &GL_object.mContextList);

    up_write(&GL_object.mSem);

    return 0;
}

static int ddpeClose(struct inode* inode, struct file* file)
{
    struct DDPEOpenContext* ctx;


    ctx = (struct DDPEOpenContext *)file->private_data;
    down_write(&GL_object.mSem);
    if ( !GL_object.mAttached )
    {
        dbg("disconnected close for 0x%p (0x%p)", ctx, ctx->excluded);
        ctx->modified = true;
        ctx->closed = true;
    }
    else
    {
        IProcessExcluder* procexcl;


        procexcl = GL_object.mProcExcl;
        procexcl->deregisterProcess(procexcl->object, ctx->excluded);
        talpa_list_del(&ctx->head);
        kfree(ctx);
    }
    up_write(&GL_object.mSem);

    return 0;
}

static int ddpeIoctl(struct inode* inode, struct file* file, unsigned int cmd, unsigned long arg)
{
    struct DDPEOpenContext* ctx;
    int ret = 0;


    /* We should check whether file was opened with write permission
       here but we intentionally do not. Our userspace users want it
       that way. */

    ctx = (struct DDPEOpenContext *)file->private_data;
    down_read(&GL_object.mSem);
    if ( !GL_object.mAttached )
    {
        dbg("disconnected ioctl for 0x%p (0x%p)", ctx, ctx->excluded);
        ctx->modified = true;
        switch ( cmd )
        {
            case TLPPEIOC_ACTIVE:
                ctx->state = true;
                break;
            case TLPPEIOC_IDLE:
                ctx->state = false;
                break;
            default:
                ret = -ENOTTY;
        }
    }
    else
    {
        IProcessExcluder* procexcl;


        procexcl = GL_object.mProcExcl;
        switch ( cmd )
        {
            case TLPPEIOC_ACTIVE:
                ctx->excluded = procexcl->active(procexcl->object, ctx->excluded);
                break;
            case TLPPEIOC_IDLE:
                ctx->excluded = procexcl->idle(procexcl->object, ctx->excluded);
                break;
            default:
                ret = -ENOTTY;
        }
    }
    up_read(&GL_object.mSem);

    return ret;
}

static bool attach(void* self)
{
    down_write(&this->mSem);

    if ( !this->mAttached )
    {
        const ICoreApplicationControl* (*core)(void) = NULL;
        const IPortabilityApplicationControl* (*portability)(void) = NULL;


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
        core = (const ICoreApplicationControl* (*)(void))inter_module_get("TALPA_Core");
        portability = (const IPortabilityApplicationControl* (*)(void))inter_module_get("TALPA_Portability");
#else
        core = symbol_get(TALPA_Core);
        portability = symbol_get(TALPA_Portability);
#endif
        if ( core && portability )
        {
            struct DDPEOpenContext* ctx;
            struct DDPEOpenContext* tmp;


            this->mProcExcl = core()->processExcluder();
            this->mAttached = true;

            talpa_list_for_each_entry_safe(ctx, tmp, &GL_object.mContextList, head)
            {
                if ( ctx->modified )
                {
                    ctx->modified = false;
                    if ( ctx->closed )
                    {
                        dbg("replaying previous disconnected close for 0x%p (0x%p)", ctx, ctx->excluded);
                        this->mProcExcl->deregisterProcess(this->mProcExcl->object, ctx->excluded);
                        talpa_list_del(&ctx->head);
                        kfree(ctx);
                    }
                    else if ( ctx->state )
                    {
                        dbg("replaying previous disconnected activate ioctl for 0x%p (0x%p)", ctx, ctx->excluded);
                        ctx->excluded = this->mProcExcl->active(this->mProcExcl->object, ctx->excluded);
                    }
                    else
                    {
                        dbg("replaying previous disconnected idle ioctl for 0x%p (0x%p)", ctx, ctx->excluded);
                        ctx->excluded = this->mProcExcl->idle(this->mProcExcl->object, ctx->excluded);
                    }
                }
            }

            /* Expose the configuration */
            this->mConfigurator = portability()->configurator();
            this->mConfigurator->attach(this->mConfigurator->object, ECG_FilterInterfaces, &this->i_IConfigurable);

            info("Attached");

            up_write(&this->mSem);

            return true;
        }
        else
        {
            if ( core )
            {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
                inter_module_put("TALPA_Core");
#else
                symbol_put(TALPA_Core);
#endif
            }

            if ( portability )
            {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
                inter_module_put("TALPA_Portability");
#else
                symbol_put(TALPA_Portability);
#endif
            }
        }
    }

    up_write(&this->mSem);

    return false;
}

int talpa_pedevice_attach(void)
{
    return (GL_object.attach(&GL_object))?1:0;
}

static bool detach(void* self)
{
    down_write(&this->mSem);

    if ( this->mAttached )
    {
        this->mConfigurator->detach(this->mConfigurator->object, &this->i_IConfigurable);
        this->mProcExcl = NULL;
        this->mAttached = false;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
        inter_module_put("TALPA_Core");
        inter_module_put("TALPA_Portability");
#else
        symbol_put(TALPA_Core);
        symbol_put(TALPA_Portability);
#endif
        info("Detached");

        up_write(&this->mSem);

        return true;
    }

    up_write(&this->mSem);

    return false;
}

int talpa_pedevice_detach(void)
{
    return (GL_object.detach(&GL_object))?1:0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
EXPORT_SYMBOL(talpa_pedevice_attach);
EXPORT_SYMBOL(talpa_pedevice_detach);
#else
EXPORT_SYMBOL_NOVERS(talpa_pedevice_attach);
EXPORT_SYMBOL_NOVERS(talpa_pedevice_detach);
#endif

/*
 * IConfigurable.
 */
static const char* configName(const void* self)
{
    return "DeviceDriverProcessExclusion";
}

static const PODConfigurationElement* allConfig(const void* self)
{
    return this->mConfig;
}

static const char* config(const void* self, const char* name)
{
    PODConfigurationElement*    cfgElement;


    /*
     * Find the named item.
     */
    for (cfgElement = this->mConfig; cfgElement->name != 0; cfgElement++)
    {
        if (strcmp(name, cfgElement->name) == 0)
        {
            break;
        }
    }

    /*
     * Return what was found else a null pointer.
     */
    if (cfgElement->name != 0)
    {
        return cfgElement->value;
    }
    return 0;
}

static void  setConfig(void* self, const char* name, const char* value)
{
   PODConfigurationElement*    cfgElement;


    /*
     * Find the named item.
     */
    for (cfgElement = this->mConfig; cfgElement->name != 0; cfgElement++)
    {
        if (strcmp(name, cfgElement->name) == 0)
        {
            break;
        }
    }

    /*
     * Cant set that which does not exist!
     */
    if (cfgElement->name == 0)
    {
        return;
    }

    /*
     * OK time to do some work...
     */
    if (strcmp(name, CFG_LOCATION) == 0)
    {
        strncpy(this->mLocationConfigData[0].value, value, DDPE_CFGLOCATIONSIZE);
    }

    return;
}

/*
 * End of device_driver_process_exclusion.c
 */

