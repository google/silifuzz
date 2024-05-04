/*
 * pfmlib_intel_knl_unc_cha.c : Intel KnightsLanding CHA uncore PMU
 *
 * Copyright (c) 2016 Intel Corp. All rights reserved
 * Contributed by Peinan Zhang <peinan.zhang@intel.com>
 *
 * Intel Knights Mill CHA uncore PMU support added April 2018
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
 */
#include <sys/types.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* private headers */
#include "pfmlib_priv.h"
#include "pfmlib_intel_x86_priv.h"
#include "pfmlib_intel_snbep_unc_priv.h"
#include "events/intel_knl_unc_cha_events.h"

#define DEFINE_CHA_BOX(n) \
pfmlib_pmu_t intel_knl_unc_cha##n##_support = { \
	.desc			= "Intel KnightLanding CHA "#n" uncore", \
	.name			= "knl_unc_cha"#n, \
	.perf_name		= "uncore_cha_"#n, \
	.pmu			= PFM_PMU_INTEL_KNL_UNC_CHA##n, \
	.pme_count		= LIBPFM_ARRAY_SIZE(intel_knl_unc_cha_pe), \
	.type			= PFM_PMU_TYPE_UNCORE, \
	.num_cntrs		= 4, \
	.num_fixed_cntrs	= 0, \
	.max_encoding		= 1, \
	.pe			= intel_knl_unc_cha_pe,   \
        .atdesc                 = snbep_unc_mods,           \
	.flags			= PFMLIB_PMU_FL_RAW_UMASK,  \
	.pmu_detect		= pfm_intel_knl_unc_detect, \
	.get_event_encoding[PFM_OS_NONE] = pfm_intel_snbep_unc_get_encoding, \
	 PFMLIB_ENCODE_PERF(pfm_intel_snbep_unc_get_perf_encoding), \
	 PFMLIB_OS_DETECT(pfm_intel_x86_perf_detect), \
	.get_event_first	= pfm_intel_x86_get_event_first, \
	.get_event_next		= pfm_intel_x86_get_event_next, \
	.event_is_valid		= pfm_intel_x86_event_is_valid, \
	.validate_table		= pfm_intel_x86_validate_table, \
	.get_event_info		= pfm_intel_x86_get_event_info, \
	.get_event_attr_info	= pfm_intel_x86_get_event_attr_info, \
	PFMLIB_VALID_PERF_PATTRS(pfm_intel_snbep_unc_perf_validate_pattrs), \
	.get_event_nattrs	= pfm_intel_x86_get_event_nattrs, \
}; \
 \
pfmlib_pmu_t intel_knm_unc_cha##n##_support = { \
	.desc			= "Intel Knights Mill CHA "#n" uncore", \
	.name			= "knm_unc_cha"#n, \
	.perf_name		= "uncore_cha_"#n, \
	.pmu			= PFM_PMU_INTEL_KNM_UNC_CHA##n, \
	.pme_count		= LIBPFM_ARRAY_SIZE(intel_knl_unc_cha_pe), \
	.type			= PFM_PMU_TYPE_UNCORE, \
	.num_cntrs		= 4, \
	.num_fixed_cntrs	= 0, \
	.max_encoding		= 1, \
	.pe			= intel_knl_unc_cha_pe,   \
        .atdesc                 = snbep_unc_mods,           \
	.flags			= PFMLIB_PMU_FL_RAW_UMASK,  \
	.pmu_detect		= pfm_intel_knm_unc_detect, \
	.get_event_encoding[PFM_OS_NONE] = pfm_intel_snbep_unc_get_encoding, \
	 PFMLIB_ENCODE_PERF(pfm_intel_snbep_unc_get_perf_encoding), \
	 PFMLIB_OS_DETECT(pfm_intel_x86_perf_detect), \
	.get_event_first	= pfm_intel_x86_get_event_first, \
	.get_event_next		= pfm_intel_x86_get_event_next, \
	.event_is_valid		= pfm_intel_x86_event_is_valid, \
	.validate_table		= pfm_intel_x86_validate_table, \
	.get_event_info		= pfm_intel_x86_get_event_info, \
	.get_event_attr_info	= pfm_intel_x86_get_event_attr_info, \
	PFMLIB_VALID_PERF_PATTRS(pfm_intel_snbep_unc_perf_validate_pattrs), \
	.get_event_nattrs	= pfm_intel_x86_get_event_nattrs, \
};

DEFINE_CHA_BOX(0);
DEFINE_CHA_BOX(1);
DEFINE_CHA_BOX(2);
DEFINE_CHA_BOX(3);
DEFINE_CHA_BOX(4);
DEFINE_CHA_BOX(5);
DEFINE_CHA_BOX(6);
DEFINE_CHA_BOX(7);
DEFINE_CHA_BOX(8);
DEFINE_CHA_BOX(9);
DEFINE_CHA_BOX(10);
DEFINE_CHA_BOX(11);
DEFINE_CHA_BOX(12);
DEFINE_CHA_BOX(13);
DEFINE_CHA_BOX(14);
DEFINE_CHA_BOX(15);
DEFINE_CHA_BOX(16);
DEFINE_CHA_BOX(17);
DEFINE_CHA_BOX(18);
DEFINE_CHA_BOX(19);
DEFINE_CHA_BOX(20);
DEFINE_CHA_BOX(21);
DEFINE_CHA_BOX(22);
DEFINE_CHA_BOX(23);
DEFINE_CHA_BOX(24);
DEFINE_CHA_BOX(25);
DEFINE_CHA_BOX(26);
DEFINE_CHA_BOX(27);
DEFINE_CHA_BOX(28);
DEFINE_CHA_BOX(29);
DEFINE_CHA_BOX(30);
DEFINE_CHA_BOX(31);
DEFINE_CHA_BOX(32);
DEFINE_CHA_BOX(33);
DEFINE_CHA_BOX(34);
DEFINE_CHA_BOX(35);
DEFINE_CHA_BOX(36);
DEFINE_CHA_BOX(37);


