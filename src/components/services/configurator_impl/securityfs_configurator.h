/*
 * securityfs_configurator.h
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
#ifndef H_SECURITYFSCONFIGURATOR
#define H_SECURITYFSCONFIGURATOR

#include <linux/security.h>

#include "common/bool.h"
#include "common/locking.h"
#include "common/list.h"
#include "configurator/econfiguration_group.h"
#include "configurator/iconfigurator.h"


struct configurationGroup
{
    talpa_list_head     head;
    unsigned int        usecnt;
    EConfigurationGroup id;
    struct dentry       *dentry;
    talpa_list_head     items;
};

struct configurationItem
{
    talpa_list_head             head;
    IConfigurable               *item;
    struct dentry               *dentry;
    unsigned int                count;
    struct configurationElement *elements;
};

struct configurationElement
{
    IConfigurable   *owner;
    struct dentry   *dentry;
    char            *name;
    unsigned int    size;
};

typedef struct tag_SecurityfsConfigurator
{
    IConfigurator           i_IConfigurator;
    void                    (*delete)(struct tag_SecurityfsConfigurator* object);
    talpa_mutex_t           mSemaphore;
    struct dentry           *mRoot;
    talpa_list_head         mGroups;
} SecurityfsConfigurator;

/*
 * Object creation/destruction.
 */
SecurityfsConfigurator* newSecurityfsConfigurator(void);

#endif

/*
 * End of securityfs_configurator.h
 */
