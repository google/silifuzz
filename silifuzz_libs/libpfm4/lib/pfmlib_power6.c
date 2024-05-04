/*
 * pfmlib_power6.c : IBM Power6 support
 *
 * Copyright (C) IBM Corporation, 2009.  All rights reserved.
 * Contributed by Corey Ashford (cjashfor@us.ibm.com)
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
#include "pfmlib_power_priv.h"
#include "events/power6_events.h"

static int
pfm_power6_detect(void* this)
{
	if (__is_processor(PV_POWER6))
		return PFM_SUCCESS;
	return PFM_ERR_NOTSUPP;
}

pfmlib_pmu_t power6_support={
	.desc			= "POWER6",
	.name			= "power6",
	.pmu			= PFM_PMU_POWER6,
	.pme_count		= LIBPFM_ARRAY_SIZE(power6_pe),
	.type			= PFM_PMU_TYPE_CORE,
	.num_cntrs		= 4,
	.num_fixed_cntrs	= 2,
	.max_encoding		= 1,
	.pe			= power6_pe,
	.pmu_detect		= pfm_power6_detect,
	.get_event_encoding[PFM_OS_NONE] = pfm_gen_powerpc_get_encoding,
	 PFMLIB_ENCODE_PERF(pfm_gen_powerpc_get_perf_encoding),
	 PFMLIB_VALID_PERF_PATTRS(pfm_gen_powerpc_perf_validate_pattrs),
	.get_event_first	= pfm_gen_powerpc_get_event_first,
	.get_event_next		= pfm_gen_powerpc_get_event_next,
	.event_is_valid		= pfm_gen_powerpc_event_is_valid,
	.validate_table		= pfm_gen_powerpc_validate_table,
	.get_event_info		= pfm_gen_powerpc_get_event_info,
	.get_event_attr_info	= pfm_gen_powerpc_get_event_attr_info,
};
