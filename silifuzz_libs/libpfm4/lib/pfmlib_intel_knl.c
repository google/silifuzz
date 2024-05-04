/*
 * pfmlib_intel_knl.c : Intel Knights Landing core PMU
 *
 * Copyright (c) 2016 Intel Corp. All rights reserved
 * Contributed by Peinan Zhang  <peinan.zhang@intel.com>
 *
 * Intel Knights Mill core PMU support added March 2018
 * Based on Intel's Knights Landing event table, which is shared with Knights Mill
 * Contributed by Heike Jagode <jagode@icl.utk.edu>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
 * CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
 * OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * Based on Intel Software Optimization Guide 2015
 */

/* private headers */
#include "pfmlib_priv.h"
#include "pfmlib_intel_x86_priv.h"
#include "events/intel_knl_events.h"

static const int knl_models[] = {
	87, /* knights landing */
	0
};

static const int knm_models[] = {
        133, /* knights mill */
        0
};

static int
pfm_intel_knl_init(void *this)
{
	pfm_intel_x86_cfg.arch_version = 2;
	return PFM_SUCCESS;
}

pfmlib_pmu_t intel_knl_support={
	.desc			= "Intel Knights Landing",
	.name			= "knl",
	.pmu			= PFM_PMU_INTEL_KNL,
	.pme_count		= LIBPFM_ARRAY_SIZE(intel_knl_pe),
	.type			= PFM_PMU_TYPE_CORE,
	.num_cntrs		= 2,
	.num_fixed_cntrs	= 3,
	.max_encoding		= 2,
	.pe			= intel_knl_pe,
	.atdesc			= intel_x86_mods,
	.flags			= PFMLIB_PMU_FL_RAW_UMASK
				| INTEL_X86_PMU_FL_ECMASK,
	.supported_plm		= INTEL_X86_PLM,

	.cpu_family		= 6,
	.cpu_models		= knl_models,
	.pmu_detect		= pfm_intel_x86_model_detect,
	.pmu_init		= pfm_intel_knl_init,

	.get_event_encoding[PFM_OS_NONE] = pfm_intel_x86_get_encoding,
	 PFMLIB_ENCODE_PERF(pfm_intel_x86_get_perf_encoding),

	.get_event_first	= pfm_intel_x86_get_event_first,
	.get_event_next		= pfm_intel_x86_get_event_next,
	.event_is_valid		= pfm_intel_x86_event_is_valid,
	.validate_table		= pfm_intel_x86_validate_table,
	.get_event_info		= pfm_intel_x86_get_event_info,
	.get_event_attr_info	= pfm_intel_x86_get_event_attr_info,
	PFMLIB_VALID_PERF_PATTRS(pfm_intel_x86_perf_validate_pattrs),
	.get_event_nattrs	= pfm_intel_x86_get_event_nattrs,
};

pfmlib_pmu_t intel_knm_support={
        .desc                   = "Intel Knights Mill",
        .name                   = "knm",
        .pmu                    = PFM_PMU_INTEL_KNM,
        .pme_count              = LIBPFM_ARRAY_SIZE(intel_knl_pe),
        .type                   = PFM_PMU_TYPE_CORE,
        .num_cntrs              = 2,
        .num_fixed_cntrs        = 3,
        .max_encoding           = 2,
        .pe                     = intel_knl_pe,
        .atdesc                 = intel_x86_mods,
        .flags                  = PFMLIB_PMU_FL_RAW_UMASK
                                | INTEL_X86_PMU_FL_ECMASK,
        .supported_plm          = INTEL_X86_PLM,

        .cpu_family             = 6,
        .cpu_models             = knm_models,
        .pmu_detect             = pfm_intel_x86_model_detect,
        .pmu_init               = pfm_intel_knl_init,

        .get_event_encoding[PFM_OS_NONE] = pfm_intel_x86_get_encoding,
         PFMLIB_ENCODE_PERF(pfm_intel_x86_get_perf_encoding),

        .get_event_first        = pfm_intel_x86_get_event_first,
        .get_event_next         = pfm_intel_x86_get_event_next,
        .event_is_valid         = pfm_intel_x86_event_is_valid,
        .validate_table         = pfm_intel_x86_validate_table,
        .get_event_info         = pfm_intel_x86_get_event_info,
        .get_event_attr_info    = pfm_intel_x86_get_event_attr_info,
        PFMLIB_VALID_PERF_PATTRS(pfm_intel_x86_perf_validate_pattrs),
        .get_event_nattrs       = pfm_intel_x86_get_event_nattrs,
};
