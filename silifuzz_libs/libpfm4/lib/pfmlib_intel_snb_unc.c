/*
 * pfmlib_intel_snb_unc.c : Intel SandyBridge C-Box uncore PMU
 *
 * Copyright (c) 2012 Google, Inc
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
#include "pfmlib_priv.h"
#include "pfmlib_intel_x86_priv.h"

#define INTEL_SNB_UNC_ATTRS \
	(_INTEL_X86_ATTR_I|_INTEL_X86_ATTR_E|_INTEL_X86_ATTR_C)

#include "events/intel_snb_unc_events.h"

static const int snb_models[] = {
	42, /* Sandy Bridge (Core i7 26xx, 25xx) */
	0
};

#define SNB_UNC_CBOX(n, p) \
pfmlib_pmu_t intel_snb_unc_cbo##n##_support={ \
	.desc			= "Intel Sandy Bridge C-box"#n" uncore", \
	.name			= "snb_unc_cbo"#n, \
	.perf_name		= "uncore_cbox_"#n, \
	.pmu			= PFM_PMU_INTEL_SNB_UNC_CB##n, \
	.pme_count		= LIBPFM_ARRAY_SIZE(intel_snb_unc_##p##_pe), \
	.type			= PFM_PMU_TYPE_UNCORE, \
	.num_cntrs		= 2, \
	.num_fixed_cntrs	= 1, \
	.max_encoding		= 1,\
	.pe			= intel_snb_unc_##p##_pe, \
	.atdesc			= intel_x86_mods, \
	.flags			= PFMLIB_PMU_FL_RAW_UMASK\
				| PFMLIB_PMU_FL_NO_SMPL,\
	.cpu_family		= 6,\
	.cpu_models		= snb_models, \
	.pmu_detect		= pfm_intel_x86_model_detect,\
	.get_event_encoding[PFM_OS_NONE] = pfm_intel_x86_get_encoding, \
	 PFMLIB_ENCODE_PERF(pfm_intel_nhm_unc_get_perf_encoding), \
	 PFMLIB_OS_DETECT(pfm_intel_x86_perf_detect), \
	.get_event_first	= pfm_intel_x86_get_event_first, \
	.get_event_next		= pfm_intel_x86_get_event_next, \
	.event_is_valid		= pfm_intel_x86_event_is_valid, \
	.validate_table		= pfm_intel_x86_validate_table, \
	.get_event_info		= pfm_intel_x86_get_event_info, \
	.get_event_attr_info	= pfm_intel_x86_get_event_attr_info, \
	 PFMLIB_VALID_PERF_PATTRS(pfm_intel_x86_perf_validate_pattrs),\
	.get_event_nattrs	= pfm_intel_x86_get_event_nattrs,\
}

SNB_UNC_CBOX(0, cbo0);
SNB_UNC_CBOX(1, cbo);
SNB_UNC_CBOX(2, cbo);
SNB_UNC_CBOX(3, cbo);
