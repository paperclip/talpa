/*
 * evaluation_report_impl.h
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
#ifndef H_EVALUATIONREPORT
#define H_EVALUATIONREPORT

#include <asm/atomic.h>

#include <common/bool.h>
#include <common/talpa.h>
#include <common/list.h>

#include "intercept_filters/eintercept_action.h"
#include "intercept_filters/ievaluation_report.h"

typedef struct
{
    talpa_list_head list;
    int             id;
    int             size;
    void*           data;
} EvaluationStorage;

typedef struct tag_EvaluationReportImpl
{
    IEvaluationReport   i_IEvaluationReport;
    void                (*delete)(struct tag_EvaluationReportImpl* object);

    atomic_t            mRefCnt;
    talpa_list_head     mCustom;
    EInterceptAction    mRecommendedAction;
    int                 mTimeouts;
    int                 mError;
    bool                mExternallyVetted;
} EvaluationReportImpl;

/*
 * Object Creators.
 */
EvaluationReportImpl* newEvaluationReportImpl(const int curr_timeouts);


#endif

/*
 * End of evaluation_report_impl.h
 */


