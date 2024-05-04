/*
 * pfmlib_amd64_fam17h.c : AMD64 Family 17h
 *
 * Copyright (c) 2017 Google, Inc
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
 */

/* private headers */
#include "pfmlib_priv.h"
#include "pfmlib_amd64_priv.h"
#include "events/amd64_events_fam17h_zen1.h"
#include "events/amd64_events_fam17h_zen2.h"

/*
 * This function detects ZEN1 for the deprecated
 * amd_fam17h pmu model name.
 */
static int
pfm_amd64_family_detect_zen1(void *this)
{
	int ret, rev;

	ret = pfm_amd64_detect(this);
	if (ret != PFM_SUCCESS)
		return ret;

	rev = pfm_amd64_cfg.revision;
	return rev == PFM_PMU_AMD64_FAM17H_ZEN1 ? PFM_SUCCESS: PFM_ERR_NOTSUPP;
}

/*
 * Deprecated PMU model, kept here for backward compatibility.
 * Should use amd_fam17h_zen1 instead.
 */
pfmlib_pmu_t amd64_fam17h_deprecated_support={
	.desc			= "AMD64 Fam17h Zen1 (deprecated - use amd_fam17h_zen1 instead)",
	.name			= "amd64_fam17h",
	.pmu			= PFM_PMU_AMD64_FAM17H,
	.pmu_rev		= AMD64_FAM17H,
	.pme_count		= LIBPFM_ARRAY_SIZE(amd64_fam17h_zen1_pe),
	.type			= PFM_PMU_TYPE_CORE,
	.supported_plm		= AMD64_FAM10H_PLM,
	.num_cntrs		= 6,
	.max_encoding		= 1,
	.pe			= amd64_fam17h_zen1_pe,
	.atdesc			= amd64_mods,
	.flags			= PFMLIB_PMU_FL_RAW_UMASK | PFMLIB_PMU_FL_DEPR,
	.cpu_family		= PFM_PMU_AMD64_FAM17H,
	.pmu_detect		= pfm_amd64_family_detect_zen1,
	.get_event_encoding[PFM_OS_NONE] = pfm_amd64_get_encoding,
	 PFMLIB_ENCODE_PERF(pfm_amd64_get_perf_encoding),
	.get_event_first	= pfm_amd64_get_event_first,
	.get_event_next		= pfm_amd64_get_event_next,
	.event_is_valid		= pfm_amd64_event_is_valid,
	.validate_table		= pfm_amd64_validate_table,
	.get_event_info		= pfm_amd64_get_event_info,
	.get_event_attr_info	= pfm_amd64_get_event_attr_info,
	 PFMLIB_VALID_PERF_PATTRS(pfm_amd64_perf_validate_pattrs),
	.get_event_nattrs	= pfm_amd64_get_event_nattrs,
};

pfmlib_pmu_t amd64_fam17h_zen1_support={
	.desc			= "AMD64 Fam17h Zen1",
	.name			= "amd64_fam17h_zen1",
	.pmu			= PFM_PMU_AMD64_FAM17H_ZEN1,
	.pmu_rev		= 0,
	.pme_count		= LIBPFM_ARRAY_SIZE(amd64_fam17h_zen1_pe),
	.type			= PFM_PMU_TYPE_CORE,
	.supported_plm		= AMD64_FAM10H_PLM,
	.num_cntrs		= 6,
	.max_encoding		= 1,
	.pe			= amd64_fam17h_zen1_pe,
	.atdesc			= amd64_mods,
	.flags			= PFMLIB_PMU_FL_RAW_UMASK,
	.cpu_family		= PFM_PMU_AMD64_FAM17H_ZEN1,
	.pmu_detect		= pfm_amd64_family_detect,
	.get_event_encoding[PFM_OS_NONE] = pfm_amd64_get_encoding,
	 PFMLIB_ENCODE_PERF(pfm_amd64_get_perf_encoding),
	.get_event_first	= pfm_amd64_get_event_first,
	.get_event_next		= pfm_amd64_get_event_next,
	.event_is_valid		= pfm_amd64_event_is_valid,
	.validate_table		= pfm_amd64_validate_table,
	.get_event_info		= pfm_amd64_get_event_info,
	.get_event_attr_info	= pfm_amd64_get_event_attr_info,
	 PFMLIB_VALID_PERF_PATTRS(pfm_amd64_perf_validate_pattrs),
	.get_event_nattrs	= pfm_amd64_get_event_nattrs,
};

pfmlib_pmu_t amd64_fam17h_zen2_support={
	.desc			= "AMD64 Fam17h Zen2",
	.name			= "amd64_fam17h_zen2",
	.pmu			= PFM_PMU_AMD64_FAM17H_ZEN2,
	.pmu_rev		= 0,
	.pme_count		= LIBPFM_ARRAY_SIZE(amd64_fam17h_zen2_pe),
	.type			= PFM_PMU_TYPE_CORE,
	.supported_plm		= AMD64_FAM10H_PLM,
	.num_cntrs		= 6,
	.max_encoding		= 1,
	.pe			= amd64_fam17h_zen2_pe,
	.atdesc			= amd64_mods,
	.flags			= PFMLIB_PMU_FL_RAW_UMASK,
	.cpu_family		= PFM_PMU_AMD64_FAM17H_ZEN2,
	.pmu_detect		= pfm_amd64_family_detect,
	.get_event_encoding[PFM_OS_NONE] = pfm_amd64_get_encoding,
	 PFMLIB_ENCODE_PERF(pfm_amd64_get_perf_encoding),
	.get_event_first	= pfm_amd64_get_event_first,
	.get_event_next		= pfm_amd64_get_event_next,
	.event_is_valid		= pfm_amd64_event_is_valid,
	.validate_table		= pfm_amd64_validate_table,
	.get_event_info		= pfm_amd64_get_event_info,
	.get_event_attr_info	= pfm_amd64_get_event_attr_info,
	 PFMLIB_VALID_PERF_PATTRS(pfm_amd64_perf_validate_pattrs),
	.get_event_nattrs	= pfm_amd64_get_event_nattrs,
};
