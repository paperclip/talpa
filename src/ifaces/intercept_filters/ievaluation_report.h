/*
 * ievaluation_report.h
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
#ifndef H_IEVALUATIONREPORT
#define H_IEVALUATIONREPORT

#include <common/bool.h>

#include "eintercept_action.h"

typedef struct
{
    void                   (*get)                    (void* self);
    void*                  (*customData)             (const void* self, int id, int* size);
    void                   (*setCustomData)          (void* self, int id, void* data, int size);
    EInterceptAction       (*recommendedAction)      (const void* self);
    void                   (*setRecommendedAction)   (void* self, EInterceptAction action);
    int                    (*consecutiveTimeouts)    (const void* self);
    int                    (*errorCode)              (const void* self);
    void                   (*setErrorCode)           (void* self, int errCode);
    bool                   (*hasBeenExternallyVetted)(const void* self);
    void                   (*externallyVetted)       (void* self);
    /*
     *  Object supporting this interface instance.
     */
    void*                  object;
    void                   (*delete)                (void* self);
} IEvaluationReport;

#endif

/*
 * End of ievaluation_report.h
 */

