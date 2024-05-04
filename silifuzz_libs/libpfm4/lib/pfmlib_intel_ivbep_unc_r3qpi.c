/*
 * pfmlib_intel_ivbep_r3qpi.c : Intel IvyBridge-EP R3QPI uncore PMU
 *
 * Copyright (c) 2014 Google Inc. All rights reserved
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
#include <sys/types.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* private headers */
#include "pfmlib_priv.h"
#include "pfmlib_intel_x86_priv.h"
#include "pfmlib_intel_snbep_unc_priv.h"
#include "events/intel_ivbep_unc_r3qpi_events.h"

#define DEFINE_R3QPI_BOX(n) \
pfmlib_pmu_t intel_ivbep_unc_r3qpi##n##_support = {\
	.desc			= "Intel Ivy Bridge-EP R3QPI"#n" uncore", \
	.name			= "ivbep_unc_r3qpi"#n,\
	.perf_name		= "uncore_r3qpi_"#n, \
	.pmu			= PFM_PMU_INTEL_IVBEP_UNC_R3QPI##n, \
	.pme_count		= LIBPFM_ARRAY_SIZE(intel_ivbep_unc_r3_pe),\
	.type			= PFM_PMU_TYPE_UNCORE,\
	.num_cntrs		= 3,\
	.num_fixed_cntrs	= 0,\
	.max_encoding		= 1,\
	.pe			= intel_ivbep_unc_r3_pe,\
	.atdesc			= snbep_unc_mods,\
	.flags			= PFMLIB_PMU_FL_RAW_UMASK,\
	.pmu_detect		= pfm_intel_ivbep_unc_detect,\
	.get_event_encoding[PFM_OS_NONE] = pfm_intel_snbep_unc_get_encoding,\
	 PFMLIB_ENCODE_PERF(pfm_intel_snbep_unc_get_perf_encoding),\
	 PFMLIB_OS_DETECT(pfm_intel_x86_perf_detect), \
	.get_event_first	= pfm_intel_x86_get_event_first,\
	.get_event_next		= pfm_intel_x86_get_event_next,\
	.event_is_valid		= pfm_intel_x86_event_is_valid,\
	.validate_table		= pfm_intel_x86_validate_table,\
	.get_event_info		= pfm_intel_x86_get_event_info,\
	.get_event_attr_info	= pfm_intel_x86_get_event_attr_info,\
	PFMLIB_VALID_PERF_PATTRS(pfm_intel_snbep_unc_perf_validate_pattrs),\
	.get_event_nattrs	= pfm_intel_x86_get_event_nattrs,\
}
DEFINE_R3QPI_BOX(0);
DEFINE_R3QPI_BOX(1);
DEFINE_R3QPI_BOX(2);
