/*
 * pfmlib_intel_skl.c : Intel Skylake core PMU
 *
 * Copyright (c) 2015 Google, Inc
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
#include "events/intel_skl_events.h"

static const int skl_models[] = {
	78, /* Skylake mobile */
	94, /* Skylake desktop */
	142,/* KabyLake mobile */
	158,/* KabyLake desktop */
	165,/* CometLake mobile */
	166,/* CometLake */
	0
};

static const int skx_models[] = {
	85, /* Skylake X */
	0
};

static int
pfm_skx_detect(void *this)
{
	int ret;

	/* Detect SKX model numbers (skx_models) */
	ret = pfm_intel_x86_model_detect(this);
	if (ret != PFM_SUCCESS)
		return ret;

	/* SKX model with stepping < 5 */
	return pfm_intel_x86_cfg.stepping < 5 ? PFM_SUCCESS : PFM_ERR_NOTSUPP;
}


static int
pfm_clx_detect(void *this)
{
	int ret;

	/* Detect SKX model numbers (skx_models) */
	ret = pfm_intel_x86_model_detect(this);
	if (ret != PFM_SUCCESS)
		return ret;

	/* CLX is SKX model with stepping >= 5 */
	return pfm_intel_x86_cfg.stepping >= 5 ? PFM_SUCCESS : PFM_ERR_NOTSUPP;
}

static int
pfm_skl_init(void *this)
{
	pfm_intel_x86_cfg.arch_version = 4;
	return PFM_SUCCESS;
}

pfmlib_pmu_t intel_skl_support={
	.desc			= "Intel Skylake",
	.name			= "skl",
	.pmu			= PFM_PMU_INTEL_SKL,
	.pme_count		= LIBPFM_ARRAY_SIZE(intel_skl_pe),
	.type			= PFM_PMU_TYPE_CORE,
	.supported_plm		= INTEL_X86_PLM,
	.num_cntrs		= 8, /* consider with HT off by default */
	.num_fixed_cntrs	= 3,
	.max_encoding		= 2, /* offcore_response */
	.pe			= intel_skl_pe,
	.atdesc			= intel_x86_mods,
	.flags			= PFMLIB_PMU_FL_RAW_UMASK
				| INTEL_X86_PMU_FL_ECMASK,
	.cpu_family		= 6,
	.cpu_models		= skl_models,
	.pmu_detect		= pfm_intel_x86_model_detect,
	.pmu_init		= pfm_skl_init,
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
	.get_num_events		= pfm_intel_x86_get_num_events,
};

pfmlib_pmu_t intel_skx_support={
	.desc			= "Intel Skylake X",
	.name			= "skx",
	.pmu			= PFM_PMU_INTEL_SKX,
	.pme_count		= LIBPFM_ARRAY_SIZE(intel_skl_pe),
	.type			= PFM_PMU_TYPE_CORE,
	.supported_plm		= INTEL_X86_PLM,
	.num_cntrs		= 8, /* consider with HT off by default */
	.num_fixed_cntrs	= 3,
	.max_encoding		= 2, /* offcore_response */
	.pe			= intel_skl_pe,
	.atdesc			= intel_x86_mods,
	.flags			= PFMLIB_PMU_FL_RAW_UMASK
				| INTEL_X86_PMU_FL_ECMASK,
	.cpu_family		= 6,
	.cpu_models		= skx_models,
	.pmu_detect		= pfm_skx_detect,
	.pmu_init		= pfm_skl_init,
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
	.get_num_events		= pfm_intel_x86_get_num_events,
};

pfmlib_pmu_t intel_clx_support={
	.desc			= "Intel CascadeLake X",
	.name			= "clx",
	.pmu			= PFM_PMU_INTEL_CLX,
	.pme_count		= LIBPFM_ARRAY_SIZE(intel_skl_pe),
	.type			= PFM_PMU_TYPE_CORE,
	.supported_plm		= INTEL_X86_PLM,
	.num_cntrs		= 8, /* consider with HT off by default */
	.num_fixed_cntrs	= 3,
	.max_encoding		= 2, /* offcore_response */
	.pe			= intel_skl_pe,
	.atdesc			= intel_x86_mods,
	.flags			= PFMLIB_PMU_FL_RAW_UMASK
				| INTEL_X86_PMU_FL_ECMASK,
	.cpu_family		= 6,
	.cpu_models		= skx_models,
	.pmu_detect		= pfm_clx_detect,
	.pmu_init		= pfm_skl_init,
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
	.get_num_events		= pfm_intel_x86_get_num_events,
};
