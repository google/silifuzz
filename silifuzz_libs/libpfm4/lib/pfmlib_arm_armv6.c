/*
 * pfmlib_arm_armv6.c : 	support for ARMv6 chips
 *
 * Copyright (c) 2013 by Vince Weaver <vincent.weaver@maine.edu>
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
 */

#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

/* private headers */
#include "pfmlib_priv.h"			/* library private */
#include "pfmlib_arm_priv.h"

#include "events/arm_1176_events.h"        /* event tables */

static int
pfm_arm_detect_1176(void *this)
{

	int ret;

	ret = pfm_arm_detect(this);
	if (ret != PFM_SUCCESS)
		return PFM_ERR_NOTSUPP;

	if ((pfm_arm_cfg.implementer == 0x41) && /* ARM */
			(pfm_arm_cfg.part==0xb76)) { /* 1176 */
		return PFM_SUCCESS;
	}
	return PFM_ERR_NOTSUPP;
}

/* ARM1176 support */
pfmlib_pmu_t arm_1176_support={
	.desc			= "ARM1176",
	.name			= "arm_1176",
	.pmu			= PFM_PMU_ARM_1176,
	.pme_count		= LIBPFM_ARRAY_SIZE(arm_1176_pe),
	.type			= PFM_PMU_TYPE_CORE,
	.pe			= arm_1176_pe,

	.pmu_detect		= pfm_arm_detect_1176,
	.max_encoding		= 1,
	.num_cntrs		= 2,

	.get_event_encoding[PFM_OS_NONE] = pfm_arm_get_encoding,
	 PFMLIB_ENCODE_PERF(pfm_arm_get_perf_encoding),
	.get_event_first	= pfm_arm_get_event_first,
	.get_event_next		= pfm_arm_get_event_next,
	.event_is_valid		= pfm_arm_event_is_valid,
	.validate_table		= pfm_arm_validate_table,
	.get_event_info		= pfm_arm_get_event_info,
	.get_event_attr_info	= pfm_arm_get_event_attr_info,
	 PFMLIB_VALID_PERF_PATTRS(pfm_arm_perf_validate_pattrs),
	.get_event_nattrs	= pfm_arm_get_event_nattrs,
};
