/*
 * pfmlib_mips_74k.c : 	support for MIPS chips
 *
 * Copyright (c) 2011 Samara Technology Group, Inc
 * Contributed by Philip Mucci <phil.mucci@@samaratechnologygroup.com>
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
#include "pfmlib_priv.h"		/* library private */
#include "pfmlib_mips_priv.h"
#include "events/mips_74k_events.h"	/* event tables */

/* root@redhawk_RT-N16:/proc# more cpuinfo
system type             : Broadcom BCM4716 chip rev 1
processor               : 0
cpu model               : MIPS 74K V4.0
BogoMIPS                : 239.20
wait instruction        : no
microsecond timers      : yes
tlb_entries             : 64 */

static int
pfm_mips_detect_74k(void *this)
{

	int ret;

	DPRINT("mips_detect_74k\n");

        ret = pfm_mips_detect(this);
        if (ret != PFM_SUCCESS)
		return PFM_ERR_NOTSUPP;

	if (strstr(pfm_mips_cfg.model,"MIPS 74K"))
		return PFM_SUCCESS;

	return PFM_ERR_NOTSUPP;
}

/* Cortex A8 support */
pfmlib_pmu_t mips_74k_support={
	.desc			= "MIPS 74k",
	.name			= "mips_74k",
	.pmu			= PFM_PMU_MIPS_74K,
	.pme_count		= LIBPFM_ARRAY_SIZE(mips_74k_pe),
	.type			= PFM_PMU_TYPE_CORE,
	.pe			= mips_74k_pe,

	.pmu_detect		= pfm_mips_detect_74k,
	.max_encoding		= 2, /* event encoding + counter bitmask */
	.num_cntrs		= 4,

	.get_event_encoding[PFM_OS_NONE] = pfm_mips_get_encoding,
	 PFMLIB_ENCODE_PERF(pfm_mips_get_perf_encoding),
	.get_event_first	= pfm_mips_get_event_first,
	.get_event_next		= pfm_mips_get_event_next,
	.event_is_valid		= pfm_mips_event_is_valid,
	.validate_table		= pfm_mips_validate_table,
	.get_event_info		= pfm_mips_get_event_info,
	.get_event_attr_info	= pfm_mips_get_event_attr_info,
	 PFMLIB_VALID_PERF_PATTRS(pfm_mips_perf_validate_pattrs),
	.get_event_nattrs	= pfm_mips_get_event_nattrs,
	.supported_plm		= PFM_PLM0|PFM_PLM3|PFM_PLMH,
};
