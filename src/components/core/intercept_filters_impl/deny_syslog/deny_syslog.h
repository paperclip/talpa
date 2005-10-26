/*
 * deny_syslog.h
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
#ifndef H_DENYSYSLOGFILTER
#define H_DENYSYSLOGFILTER


#include "common/locking.h"
#include "intercept_filters/iintercept_filter.h"
#include "configurator/iconfigurable.h"

#define DENYSYSLOGFILTER_CFGDATASIZE      (16)

typedef struct {
    char    name[DENYSYSLOGFILTER_CFGDATASIZE];
    char    value[DENYSYSLOGFILTER_CFGDATASIZE];
} DenySyslogFilterConfigData;

typedef struct tag_DenySyslogFilter
{
    IInterceptFilter            i_IInterceptFilter;
    IConfigurable               i_IConfigurable;
    void                        (*delete)(struct tag_DenySyslogFilter* object);
    talpa_mutex_t               mConfigSerialize;
    bool                        mEnabled;
    char                        mName[64];
    PODConfigurationElement     mConfig[2];
    DenySyslogFilterConfigData  mConfigData;
} DenySyslogFilter;

/*
 * Object Creators.
 */
DenySyslogFilter* newDenySyslogFilter(const char *name);


#endif

/*
 * End of deny_syslog.h
 */

