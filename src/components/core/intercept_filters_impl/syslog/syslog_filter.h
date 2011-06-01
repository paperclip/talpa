/*
 * syslog_filter.h
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
#ifndef H_SYSLOGFILTER
#define H_SYSLOGFILTER


#include "common/locking.h"
#include "intercept_filters/iintercept_filter.h"
#include "configurator/iconfigurable.h"

#define SYSLOGFILTER_CFGDATASIZE      (16)

typedef struct {
    char    name[SYSLOGFILTER_CFGDATASIZE];
    char    value[SYSLOGFILTER_CFGDATASIZE];
} SyslogFilterConfigData;

typedef struct tag_SyslogFilter
{
    IInterceptFilter            i_IInterceptFilter;
    IConfigurable               i_IConfigurable;
    void                        (*delete)(struct tag_SyslogFilter* object);
    talpa_mutex_t               mConfigSerialize;
    bool                        mEnabled;
    char                        mName[64];
    PODConfigurationElement     mConfig[2];
    SyslogFilterConfigData      mConfigData;
} SyslogFilter;

/*
 * Object Creators.
 */
SyslogFilter* newSyslogFilter(const char *name);


#endif

/*
 * End of syslog_filter.h
 */

