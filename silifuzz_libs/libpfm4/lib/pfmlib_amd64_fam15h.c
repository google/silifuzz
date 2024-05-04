/*
 * pfmlib_amd64_fam15h.c : AMD64 Family 15h
 *
 * Copyright (c) 2011 Google, Inc
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
#include "events/amd64_events_fam15h.h"
#include "events/amd64_events_fam15h_nb.h"

pfmlib_pmu_t amd64_fam15h_interlagos_support={
	.desc			= "AMD64 Fam15h Interlagos",
	.name			= "amd64_fam15h_interlagos",
	.pmu			= PFM_PMU_AMD64_FAM15H_INTERLAGOS,
	.pmu_rev		= AMD64_FAM15H,
	.pme_count		= LIBPFM_ARRAY_SIZE(amd64_fam15h_pe),
	.type			= PFM_PMU_TYPE_CORE,
	.supported_plm		= AMD64_FAM10H_PLM,
	.num_cntrs		= 6,
	.max_encoding		= 1,
	.pe			= amd64_fam15h_pe,
	.atdesc			= amd64_mods,
	.flags			= PFMLIB_PMU_FL_RAW_UMASK,
	.cpu_family		= PFM_PMU_AMD64_FAM15H_INTERLAGOS,
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

pfmlib_pmu_t amd64_fam15h_nb_support={
	.desc			= "AMD64 Fam15h NorthBridge",
	.name			= "amd64_fam15h_nb",
	.pmu			= PFM_PMU_AMD64_FAM15H_NB,
	.perf_name		= "amd_nb",
	.pmu_rev		= 0,
	.pme_count		= LIBPFM_ARRAY_SIZE(amd64_fam15h_nb_pe),
	.type			= PFM_PMU_TYPE_UNCORE,
	.supported_plm		= 0, /* no plm support */
	.num_cntrs		= 4,
	.max_encoding		= 1,
	.pe			= amd64_fam15h_nb_pe,
	.atdesc			= amd64_mods,
	.flags			= PFMLIB_PMU_FL_RAW_UMASK,
	.cpu_family		= PFM_PMU_AMD64_FAM15H_INTERLAGOS,
	.pmu_detect		= pfm_amd64_family_detect,
	.get_event_encoding[PFM_OS_NONE] = pfm_amd64_get_encoding,
	 PFMLIB_ENCODE_PERF(pfm_amd64_get_perf_encoding),
	.get_event_first	= pfm_amd64_get_event_first,
	.get_event_next		= pfm_amd64_get_event_next,
	.event_is_valid		= pfm_amd64_event_is_valid,
	.validate_table		= pfm_amd64_validate_table,
	.get_event_info		= pfm_amd64_get_event_info,
	.get_event_attr_info	= pfm_amd64_get_event_attr_info,
	 PFMLIB_VALID_PERF_PATTRS(pfm_amd64_nb_perf_validate_pattrs),
	.get_event_nattrs	= pfm_amd64_get_event_nattrs,
};
