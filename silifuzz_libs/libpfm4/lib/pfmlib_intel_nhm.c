/*
 * pfmlib_intel_nhm.c : Intel Nehalem core PMU
 *
 * Copyright (c) 2008 Google, Inc
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
 *
 * Nehalem PMU = architectural perfmon v3 + OFFCORE + PEBS v2 + LBR
 */
/* private headers */
#include "pfmlib_priv.h"
#include "pfmlib_intel_x86_priv.h"

#if 0
static int pfm_nhm_lbr_encode(void *this, pfmlib_event_desc_t *e, uint64_t *codes, int *count, pfmlib_perf_attr_t *attrs);
static int pfm_nhm_offcore_encode(void *this, pfmlib_event_desc_t *e, uint64_t *codes, int *count, pfmlib_perf_attr_t *attrs);
#endif

#include "events/intel_nhm_events.h"

static const int nhm_models[] = {
	26,
	30,
	31,
	0
};

static const int nhm_ex_models[] = {
	46,
	0
};

static int
pfm_nhm_init(void *this)
{
	pfm_intel_x86_cfg.arch_version = 3;
	return PFM_SUCCESS;
}

/*
 * the following function implement the model
 * specific API directly available to user
 */

static const char *data_src_encodings[]={
/*  0 */	"unknown L3 cache miss",
/*  1 */	"minimal latency core cache hit. Request was satisfied by L1 data cache",
/*  2 */	"pending core cache HIT. Outstanding core cache miss to same cacheline address already underway",
/*  3 */	"data request satisfied by the L2",
/*  4 */	"L3 HIT. Local or remote home request that hit L3 in the uncore with no coherency actions required (snooping)",
/*  5 */	"L3 HIT. Local or remote home request that hit L3 and was serviced by another core with a cross core snoop where no modified copy was found (clean)",
/*  6 */	"L3 HIT. Local or remote home request that hit L3 and was serviced by another core with a cross core snoop where modified copies were found (HITM)",
/*  7 */	"reserved",
/*  8 */	"L3 MISS. Local homed request that missed L3 and was serviced by forwarded data following a cross package snoop where no modified copy was found (remote home requests are not counted)",
/*  9 */	"reserved",
/* 10 */	"L3 MISS. Local homed request that missed L3 and was serviced by local DRAM (go to shared state)",
/* 11 */	"L3 MISS. Remote homed request that missed L3 and was serviced by remote DRAM (go to shared state)",
/* 12 */	"L3 MISS. Local homed request that missed L3 and was serviced by local DRAM (go to exclusive state)",
/* 13 */	"L3 MISS. Remote homed request that missed L3 and was serviced by remote DRAM (go to exclusive state)",
/* 14 */	"reserved",
/* 15 */	"request to uncacheable memory"
};

/*
 * return data source encoding based on index in val
 * To be used with PEBS load latency filtering to decode
 * source of the load miss
 */
const char *
pfm_nhm_data_src_desc(int val)
{
	if (val > 15 || val < 0)
		return NULL;

	return data_src_encodings[val];
}

#if 0
static int
pfm_nhm_lbr_encode(void *this, pfmlib_event_desc_t *e, uint64_t *codes, int *count, pfmlib_perf_attr_t *attrs)
{
	return PFM_ERR_NOTSUPP;
}

static int
pfm_nhm_offcore_encode(void *this, pfmlib_event_desc_t *e, uint64_t *codes, int *count, pfmlib_perf_attr_t *attrs)
{
	return PFM_ERR_NOTSUPP;
}
#endif


pfmlib_pmu_t intel_nhm_support={
	.desc			= "Intel Nehalem",
	.name			= "nhm",
	.pmu			= PFM_PMU_INTEL_NHM,
	.pme_count		= LIBPFM_ARRAY_SIZE(intel_nhm_pe),
	.type			= PFM_PMU_TYPE_CORE,
	.supported_plm		= INTEL_X86_PLM,
	.num_cntrs		= 4,
	.num_fixed_cntrs	= 3,
	.max_encoding		= 2, /* because of OFFCORE_RESPONSE */
	.pe			= intel_nhm_pe,
	.atdesc			= intel_x86_mods,
	.flags			= PFMLIB_PMU_FL_RAW_UMASK
				| INTEL_X86_PMU_FL_ECMASK,
	.cpu_family		= 6,
	.cpu_models		= nhm_models,
	.pmu_detect		= pfm_intel_x86_model_detect,
	.pmu_init		= pfm_nhm_init,

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
	.can_auto_encode	= pfm_intel_x86_can_auto_encode,
};

pfmlib_pmu_t intel_nhm_ex_support={
	.desc			= "Intel Nehalem EX",
	.name			= "nhm_ex",
	.pmu			= PFM_PMU_INTEL_NHM_EX,
	.pme_count		= LIBPFM_ARRAY_SIZE(intel_nhm_pe),
	.type			= PFM_PMU_TYPE_CORE,
	.supported_plm		= INTEL_X86_PLM,
	.num_cntrs		= 4,
	.num_fixed_cntrs	= 3,
	.max_encoding		= 2, /* because of OFFCORE_RESPONSE */
	.pe			= intel_nhm_pe,
	.atdesc			= intel_x86_mods,
	.flags			= PFMLIB_PMU_FL_RAW_UMASK
				| INTEL_X86_PMU_FL_ECMASK,
	.cpu_family		= 6,
	.cpu_models		= nhm_ex_models,
	.pmu_detect		= pfm_intel_x86_model_detect,
	.pmu_init		= pfm_nhm_init,

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
	.can_auto_encode	= pfm_intel_x86_can_auto_encode,
};
