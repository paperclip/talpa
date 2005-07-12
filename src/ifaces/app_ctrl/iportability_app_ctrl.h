/*
 * iportability_app_ctrl.h
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
#ifndef H_IPORTABILITYAPPCONTROL
#define H_IPORTABILITYAPPCONTROL

#include "configurator/iconfigurator.h"
#include "filesystem/isystemroot.h"
#include "filesystem/ifilesystem_factory.h"
#include "personality/ipersonality_factory.h"
#include "process_and_thread/ithreadandprocess_factory.h"

typedef struct
{
    IConfigurator*              (*configurator)             (void);
    ISystemRoot*                (*systemRoot)               (void);
    IFilesystemFactory*         (*filesystemFactory)        (void);
    IPersonalityFactory*        (*personalityFactory)       (void);
    IThreadAndProcessFactory*   (*threadandprocessFactory)  (void);
} IPortabilityApplicationControl;

extern const IPortabilityApplicationControl* TALPA_Portability(void);

#endif

/*
 * End of iportability_app_ctrl.h
 */

