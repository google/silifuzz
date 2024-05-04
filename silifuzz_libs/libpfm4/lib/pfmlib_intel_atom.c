/*
 * pfmlib_intel_atom.c : Intel Atom PMU
 *
 * Copyright (c) 2008 Google, Inc
 * Contributed by Stephane Eranian <eranian@gmail.com>
 *
 * Based on work:
 * Copyright (c) 2006 Hewlett-Packard Development Company, L.P.
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
 *
 *
 * This file implements support for Intel Core PMU as specified in the following document:
 * 	"IA-32 Intel Architecture Software Developer's Manual - Volume 3B: System
 * 	Programming Guide"
 *
 * Intel Atom = architectural v3 + PEBS
 */
/* private headers */
#include "pfmlib_priv.h"
#include "pfmlib_intel_x86_priv.h"
#include "events/intel_atom_events.h"

static const int atom_models[] = {
	28, /* Pineview/Silverthorne */
	38, /* Lincroft */
	39, /* Penwell */
	53, /* Cloverview */
	54, /* Cedarview */
	0
};

static int
pfm_intel_atom_init(void *this)
{
	pfm_intel_x86_cfg.arch_version = 3;
	return PFM_SUCCESS;
}

pfmlib_pmu_t intel_atom_support={
	.desc			= "Intel Atom",
	.name			= "atom",
	.pmu			= PFM_PMU_INTEL_ATOM,
	.pme_count		= LIBPFM_ARRAY_SIZE(intel_atom_pe),
	.type			= PFM_PMU_TYPE_CORE,
	.num_cntrs		= 2,
	.num_fixed_cntrs	= 3,
	.max_encoding		= 1,
	.pe			= intel_atom_pe,
	.atdesc			= intel_x86_mods,
	.flags			= PFMLIB_PMU_FL_RAW_UMASK,
	.supported_plm		= INTEL_X86_PLM,

	.cpu_family		= 6,
	.cpu_models		= atom_models,
	.pmu_detect		= pfm_intel_x86_model_detect,
	.pmu_init		= pfm_intel_atom_init,

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
