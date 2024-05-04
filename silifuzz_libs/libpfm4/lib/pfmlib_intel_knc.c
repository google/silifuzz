/*
 * pfmlib_intel_knc.c : Intel Knights Corner (Xeon Phi)
 *
 * Copyright (c) 2012, Google, Inc
 * Contributed by Stephane Eranian <eranian@gmail.com>
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
 */
/* private headers */
#include "pfmlib_priv.h"			/* library private */
#include "pfmlib_intel_x86_priv.h"		/* architecture private */
#include "events/intel_knc_events.h"

static const int knc_models[] = {
	1, /* Knights Corner */
	0
};

pfmlib_pmu_t intel_knc_support={
	.desc			= "Intel Knights Corner",
	.name			= "knc",
	.pmu			= PFM_PMU_INTEL_KNC,
	.pme_count		= LIBPFM_ARRAY_SIZE(intel_knc_pe),
	.type			= PFM_PMU_TYPE_CORE,
	.num_cntrs		= 2,
	.max_encoding		= 1,
	.pe			= intel_knc_pe,
	.atdesc			= intel_x86_mods,
	.supported_plm		= INTEL_X86_PLM,

	.cpu_family		= 11,
	.cpu_models		= knc_models,
	.pmu_detect		= pfm_intel_x86_model_detect,

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
