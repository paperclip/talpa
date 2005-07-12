/*
 * syslog_filter.c
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
#include <linux/kernel.h>

#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sched.h>

#define TALPA_SUBSYS "syslog"
#include "common/talpa.h"
#include "syslog_filter.h"

/*
 * Forward declare implementation methods.
 */
static void examineFile(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFileInfo* info, IFile* file);
static void examineFilesystem(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFilesystemInfo* info);
static bool enable(void* self);
static void disable(void* self);
static bool isEnabled(const void* self);
static const char* configName(const void* self);
static const PODConfigurationElement* allConfig(const void* self);
static const char* config(const void* self, const char* name);
static void setConfig(void* self, const char* name, const char* value);
static void deleteSyslogFilter(struct tag_SyslogFilter* object);

/*
 * Constants
 */
#define CFG_STATUS          "status"
#define CFG_VALUE_ENABLED   "enabled"
#define CFG_VALUE_DISABLED  "disabled"
#define CFG_ACTION_ENABLE   "enable"
#define CFG_ACTION_DISABLE  "disable"

static char* opmsg_default = "Unknown";
static char* opmsg_open = "Open";
static char* opmsg_close = "Close";
static char* opmsg_exec = "Exec";
static char* opmsg_mount = "Mount";
static char* opmsg_umount = "Umount";

/*
 * Template Object.
 */
static SyslogFilter template_SyslogFilter =
    {
        {
            examineFile,
            examineFilesystem,
            enable,
            disable,
            isEnabled,
            0,
            (void (*)(void*))deleteSyslogFilter
        },
        {
            configName,
            allConfig,
            config,
            setConfig,
            0,
            (void (*)(void*))deleteSyslogFilter
        },
        deleteSyslogFilter,
        false,
        "default",
        {
            {0, 0, SYSLOGFILTER_CFGDATASIZE, true, true },
            {0, 0, 0, false, false }
        },
        {
            { CFG_STATUS, CFG_VALUE_DISABLED }
        }

    };
#define this    ((SyslogFilter*)self)



/*
 * Object creation/destruction.
 */
SyslogFilter* newSyslogFilter(const char *name)
{
    SyslogFilter* object;


    object = kmalloc(sizeof(template_SyslogFilter), SLAB_KERNEL);
    if (object != 0)
    {
        memcpy(object, &template_SyslogFilter, sizeof(template_SyslogFilter));
        object->i_IInterceptFilter.object = object->i_IConfigurable.object = object;
        strncpy(object->mName, name, sizeof(object->mName)-1);
        object->mName[sizeof(object->mName)-1] = 0x00;
        object->mConfig[0].name  = object->mConfigData[0].name;
        object->mConfig[0].value = object->mConfigData[0].value;
    }
    return object;
}

static void deleteSyslogFilter(struct tag_SyslogFilter* object)
{
    kfree(object);
    return;
}

/*
 * IInterceptFilter.
 */
static void examineFile(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFileInfo* info, IFile* file)
{
    char* opmsg;

    switch ( info->operation(info) )
    {
        case EFS_Open:
            opmsg = opmsg_open;
            break;
        case EFS_Close:
            opmsg = opmsg_close;
            break;
        case EFS_Exec:
            opmsg = opmsg_exec;
            break;
        default:
            opmsg = opmsg_default;
            break;
    }

    info("%s: %s[%u:%u/%u] %s of %s with flags 0%o, by %u(%u)/%u(%u)",
            this->mName,
            current->comm,
            processParentPID(current),
            current->tgid, current->pid,
            opmsg, info->filename(info), info->flags(info),
            userInfo->uid(userInfo), userInfo->euid(userInfo), userInfo->gid(userInfo), userInfo->egid(userInfo));

    return;
}

static void examineFilesystem(const void* self, IEvaluationReport* report, const IPersonality* userInfo, const IFilesystemInfo* info)
{
    char* opmsg;

    switch ( info->operation(info) )
    {
        case EFS_Mount:
            opmsg = opmsg_mount;
            break;
        case EFS_Umount:
            opmsg = opmsg_umount;
            break;
        default:
            opmsg = opmsg_default;
            break;
    }

    info("%s: %s[%u:%u/%u] %s of %s on %s, filesystem type %s, by %u(%u)/%u(%u)",
            this->mName,
            current->comm,
            processParentPID(current),
            current->tgid, current->pid,
            opmsg, info->deviceName(info), info->mountPoint(info), info->type(info),
            userInfo->uid(userInfo), userInfo->euid(userInfo), userInfo->gid(userInfo), userInfo->egid(userInfo));

    return;
}

static bool enable(void* self)
{
    if (!this->mEnabled)
    {
        this->mEnabled = true;
        strcpy(this->mConfig[0].value, CFG_VALUE_ENABLED);
        info("%s: Enabled", this->mName);
    }
    return true;
}

static void disable(void* self)
{
    if (this->mEnabled)
    {
        this->mEnabled = false;
        strcpy(this->mConfig[0].value, CFG_VALUE_DISABLED);
        info("%s: Disabled", this->mName);
    }
    return;
}

static bool isEnabled(const void* self)
{
    return this->mEnabled;
}

/*
 * IConfigurable.
 */
static const char* configName(const void* self)
{
    return this->mName;
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
    if (strcmp(name, CFG_STATUS) == 0)
    {
        if (strcmp(value, CFG_ACTION_ENABLE) == 0)
        {
            enable(this);
        }
        else if (strcmp(value, CFG_ACTION_DISABLE) == 0)
        {
            disable(this);
        }
    }
    return;
}

/*
 * End of syslog_filter.c
 */

