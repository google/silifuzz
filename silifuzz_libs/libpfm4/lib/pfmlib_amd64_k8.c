/*
 * pfmlib_amd64_k8.c : AMD64 K8
 *
 * Copyright (c) 2010 Google, Inc
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
#include "events/amd64_events_k8.h"

#define DEFINE_K8_REV(d, n, r, pmuid) \
pfmlib_pmu_t amd64_k8_##n##_support={				\
	.desc			= "AMD64 K8 "#d,		\
	.name			= "amd64_k8_"#n,		\
	.pmu			= pmuid,			\
	.pmu_rev		= r,				\
	.pme_count		= LIBPFM_ARRAY_SIZE(amd64_k8_pe),\
	.type			= PFM_PMU_TYPE_CORE,		\
	.supported_plm		= AMD64_K7_PLM,			\
	.num_cntrs		= 4,				\
	.max_encoding		= 1,				\
	.pe			= amd64_k8_pe,			\
	.atdesc			= amd64_mods,			\
	.flags			= PFMLIB_PMU_FL_RAW_UMASK,	\
								\
	.cpu_family		= pmuid,			\
	.pmu_detect		= pfm_amd64_family_detect,	\
	.get_event_encoding[PFM_OS_NONE] = pfm_amd64_get_encoding, \
	 PFMLIB_ENCODE_PERF(pfm_amd64_get_perf_encoding),	\
	.get_event_first	= pfm_amd64_get_event_first,	\
	.get_event_next		= pfm_amd64_get_event_next,	\
	.event_is_valid		= pfm_amd64_event_is_valid,	\
	.validate_table		= pfm_amd64_validate_table,	\
	.get_event_info		= pfm_amd64_get_event_info,	\
	.get_event_attr_info	= pfm_amd64_get_event_attr_info,\
	 PFMLIB_VALID_PERF_PATTRS(pfm_amd64_perf_validate_pattrs),\
	.get_event_nattrs	= pfm_amd64_get_event_nattrs,	\
	.get_num_events		= pfm_amd64_get_num_events,	\
}

DEFINE_K8_REV(RevB, revb, AMD64_K8_REV_B, PFM_PMU_AMD64_K8_REVB);
DEFINE_K8_REV(RevC, revc, AMD64_K8_REV_C, PFM_PMU_AMD64_K8_REVC);
DEFINE_K8_REV(RevD, revd, AMD64_K8_REV_D, PFM_PMU_AMD64_K8_REVD);
DEFINE_K8_REV(RevE, reve, AMD64_K8_REV_E, PFM_PMU_AMD64_K8_REVE);
DEFINE_K8_REV(RevF, revf, AMD64_K8_REV_F, PFM_PMU_AMD64_K8_REVF);
DEFINE_K8_REV(RevG, revg, AMD64_K8_REV_G, PFM_PMU_AMD64_K8_REVG);
