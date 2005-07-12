/*
 * icore_app_ctrl.h
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
#ifndef H_ICOREAPPCONTROL
#define H_ICOREAPPCONTROL

#include "configurator/iconfigurator.h"
#include "intercept_processing/iintercept_processor.h"
#include "vetting_server/ivetting_server.h"
#include "process_excluder/iprocess_excluder.h"

typedef struct
{
    IInterceptProcessor*           (*interceptProcessor)(void);
    IVettingServer*                (*vettingServer)     (void);
    IProcessExcluder*              (*processExcluder)    (void);
} ICoreApplicationControl;

extern const ICoreApplicationControl* TALPA_Core(void);

#endif

/*
 * End of icore_app_ctrl.h
 */

