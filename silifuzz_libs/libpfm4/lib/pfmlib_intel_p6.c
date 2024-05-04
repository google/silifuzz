/*
 * pfmlib_i386_p6.c : support for the P6 processor family (family=6)
 * 		      incl. Pentium II, Pentium III, Pentium Pro, Pentium M
 *
 * Copyright (c) 2005-2007 Hewlett-Packard Development Company, L.P.
 * Contributed by Stephane Eranian <eranian@hpl.hp.com>
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
#include "pfmlib_priv.h"			/* library private */
#include "pfmlib_intel_x86_priv.h"		/* architecture private */
#include "events/intel_p6_events.h"		/* generic P6 (PIII) */
#include "events/intel_pii_events.h"		/* Pentium II */
#include "events/intel_ppro_events.h"		/* Pentium Pro */
#include "events/intel_pm_events.h"		/* Pentium M */

static const int pii_models[] = {
	3, /* Pentium II */
	5, /* Pentium II Deschutes */
	6, /* Pentium II Mendocino */
	0
};

static const int ppro_models[] = {
	1, /* Pentium Pro */
	0
};

static const int piii_models[] = {
	7, /* Pentium III Katmai */
	8, /* Pentium III Coppermine */
	10,/* Pentium III Cascades */
	11,/* Pentium III Tualatin */
	0
};

static const int pm_models[] = {
	9, /* Pentium M */
	13, /* Pentium III Coppermine */
	0
};

/* Pentium II support */
pfmlib_pmu_t intel_pii_support={
	.desc			= "Intel Pentium II",
	.name			= "pii",
	.pmu			= PFM_PMU_INTEL_PII,
	.pme_count		= LIBPFM_ARRAY_SIZE(intel_pii_pe),
	.pe			= intel_pii_pe,
	.atdesc			= intel_x86_mods,
	.flags			= PFMLIB_PMU_FL_RAW_UMASK,
	.type			= PFM_PMU_TYPE_CORE,
	.supported_plm		= INTEL_X86_PLM,
	.cpu_family		= 6,
	.cpu_models		= pii_models,
	.pmu_detect		= pfm_intel_x86_model_detect,
	.num_cntrs		= 2,
	.max_encoding		= 1,

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
};

pfmlib_pmu_t intel_p6_support={
	.desc			= "Intel P6 Processor Family",
	.name			= "p6",
	.pmu			= PFM_PMU_I386_P6,
	.pme_count		= LIBPFM_ARRAY_SIZE(intel_p6_pe),
	.pe			= intel_p6_pe,
	.atdesc			= intel_x86_mods,
	.flags			= PFMLIB_PMU_FL_RAW_UMASK,
	.type			= PFM_PMU_TYPE_CORE,
	.supported_plm		= INTEL_X86_PLM,

	.cpu_family		= 6,
	.cpu_models		= piii_models,
	.pmu_detect		= pfm_intel_x86_model_detect,
	.num_cntrs		= 2,
	.max_encoding		= 1,

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
};

pfmlib_pmu_t intel_ppro_support={
	.desc			= "Intel Pentium Pro",
	.name			= "ppro",
	.pmu			= PFM_PMU_INTEL_PPRO,
	.pme_count		= LIBPFM_ARRAY_SIZE(intel_ppro_pe),
	.pe			= intel_ppro_pe,
	.atdesc			= intel_x86_mods,
	.flags			= PFMLIB_PMU_FL_RAW_UMASK,
	.type			= PFM_PMU_TYPE_CORE,
	.supported_plm		= INTEL_X86_PLM,

	.cpu_family		= 6,
	.cpu_models		= ppro_models,
	.pmu_detect		= pfm_intel_x86_model_detect,
	.num_cntrs		= 2,
	.max_encoding		= 1,

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
};

/* Pentium M support */
pfmlib_pmu_t intel_pm_support={
	.desc			= "Intel Pentium M",
	.name			= "pm",
	.pmu			= PFM_PMU_I386_PM,
	.pe			= intel_pm_pe,
	.atdesc			= intel_x86_mods,
	.flags			= PFMLIB_PMU_FL_RAW_UMASK,
	.supported_plm		= INTEL_X86_PLM,

	.cpu_family		= 6,
	.cpu_models		= pm_models,
	.pmu_detect		= pfm_intel_x86_model_detect,
	.pme_count		= LIBPFM_ARRAY_SIZE(intel_pm_pe),
	.type			= PFM_PMU_TYPE_CORE,
	.num_cntrs		= 2,
	.max_encoding		= 1,

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
};
