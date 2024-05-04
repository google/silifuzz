/*
 * pfmlib_intel_x86_arch.c : Intel architectural PMU v1, v2, v3
 *
 * Copyright (c) 2005-2007 Hewlett-Packard Development Company, L.P.
 * Contributed by Stephane Eranian <eranian@hpl.hp.com>
 *
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
 * This file implements supports for the IA-32 architectural PMU as specified
 * in the following document:
 * 	"IA-32 Intel Architecture Software Developer's Manual - Volume 3B: System
 * 	Programming Guide"
 */
#include <sys/types.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* private headers */
#include "pfmlib_priv.h"			/* library private */
#include "pfmlib_intel_x86_priv.h"		/* architecture private */

#include "events/intel_x86_arch_events.h"	/* architected event table */

extern pfmlib_pmu_t intel_x86_arch_support;

static intel_x86_entry_t *x86_arch_pe;

static inline void
cpuid(unsigned int op, unsigned int *a, unsigned int *b, unsigned int *c, unsigned int *d)
{
	asm volatile("cpuid" : "=a" (*a), "=b" (*b), "=c" (*c), "=d" (*d) : "a" (op) : "memory");
}

/*
 * create architected event table
 */
static int
create_arch_event_table(unsigned int mask, int version)
{
	intel_x86_entry_t *pe;
	int i, num_events = 0;
	int m;

	DPRINT("version=%d evt_msk=0x%x\n", version, mask);

	/*
	 * first pass: count the number of supported events
	 */
	m = mask;
	for(i=0; i < 7; i++, m>>=1) {
		if ((m & 0x1)  == 0)
			num_events++;
	}
	intel_x86_arch_support.pme_count = num_events;

	pe = calloc(num_events, sizeof(intel_x86_entry_t));
	if (pe == NULL)
		return PFM_ERR_NOTSUPP;

	x86_arch_pe = pe;
	intel_x86_arch_support.pe = pe;

	/*
	 * second pass: populate the table
	 */
	m = mask;
	for(i=0; i < 7; i++, m>>=1) {
		if (!(m & 0x1)) {
			*pe = intel_x86_arch_pe[i];

			switch(version) {
			case 5:
				pe->modmsk = INTEL_V5_ATTRS;
				break;
			case 4:
				pe->modmsk = INTEL_V4_ATTRS;
				break;
			case 3:
				pe->modmsk = INTEL_V3_ATTRS;
				break;
			default:
				pe->modmsk = INTEL_V2_ATTRS;
				break;
			}
			pe++;
		}
	}
	return PFM_SUCCESS;
}

static int
check_arch_pmu(int family)
{
	union {
		unsigned int val;
		intel_x86_pmu_eax_t eax;
		intel_x86_pmu_edx_t edx;
	} eax, ecx, edx, ebx;

	/*
	 * check family number to reject for processors
	 * older than Pentium (family=5). Those processors
	 * did not have the CPUID instruction
	 */
	if (family < 5 || family == 15)
		return PFM_ERR_NOTSUPP;

	/*
	 * check if CPU supports 0xa function of CPUID
	 * 0xa started with Core Duo. Needed to detect if
	 * architected PMU is present
	 */
	cpuid(0x0, &eax.val, &ebx.val, &ecx.val, &edx.val);
	if (eax.val < 0xa)
		return PFM_ERR_NOTSUPP;

	/*
	 * extract architected PMU information
	 */
	cpuid(0xa, &eax.val, &ebx.val, &ecx.val, &edx.val);

	/*
	 * version must be greater than zero
	 */
	return eax.eax.version < 1 ? PFM_ERR_NOTSUPP : PFM_SUCCESS;
}

static int
pfm_intel_x86_arch_detect(void *this)
{
	int ret;

	ret = pfm_intel_x86_detect();
	if (ret != PFM_SUCCESS)
		return ret;

	return check_arch_pmu(pfm_intel_x86_cfg.family);
}

static int
pfm_intel_x86_arch_init(void *this)
{
	union {
		unsigned int val;
		intel_x86_pmu_eax_t eax;
		intel_x86_pmu_edx_t edx;
	} eax, ecx, edx, ebx;

	/*
	 * extract architected PMU information
	 */
	if (!pfm_cfg.forced_pmu) {
		cpuid(0xa, &eax.val, &ebx.val, &ecx.val, &edx.val);
		intel_x86_arch_support.num_cntrs = eax.eax.num_cnt;
		intel_x86_arch_support.num_fixed_cntrs = edx.edx.num_cnt;
	} else {
		eax.eax.version = 3;
		ebx.val = 0; /* no restriction */
		intel_x86_arch_support.num_cntrs = 0;
		intel_x86_arch_support.num_fixed_cntrs = 0;
	}
	/*
 	 * must be called after impl_cntrs has been initialized
 	 */
	return create_arch_event_table(ebx.val, eax.eax.version);
}

void
pfm_intel_x86_arch_terminate(void *this)
{
	/* workaround const void for intel_x86_arch_support.pe */
	if (x86_arch_pe)
		free(x86_arch_pe);
}

/* architected PMU */
pfmlib_pmu_t intel_x86_arch_support={
	.desc			= "Intel X86 architectural PMU",
	.name			= "ix86arch",
	.pmu			= PFM_PMU_INTEL_X86_ARCH,
	.pme_count		= 0,
	.pe			= NULL,
	.atdesc			= intel_x86_mods,
	.flags			= PFMLIB_PMU_FL_RAW_UMASK | PFMLIB_PMU_FL_ARCH_DFL,
	.type			= PFM_PMU_TYPE_CORE,
	.max_encoding		= 1,
	.supported_plm		= INTEL_X86_PLM,

	.pmu_detect		= pfm_intel_x86_arch_detect,
	.pmu_init		= pfm_intel_x86_arch_init,
	.pmu_terminate		= pfm_intel_x86_arch_terminate,
	.get_event_encoding[PFM_OS_NONE] = pfm_intel_x86_get_encoding,
	 PFMLIB_ENCODE_PERF(pfm_intel_x86_get_perf_encoding),
	.get_event_first	= pfm_intel_x86_get_event_first,
	.get_event_next		= pfm_intel_x86_get_event_next,
	.event_is_valid		= pfm_intel_x86_event_is_valid,
	.get_event_info		= pfm_intel_x86_get_event_info,
	.get_event_attr_info	= pfm_intel_x86_get_event_attr_info,
	PFMLIB_VALID_PERF_PATTRS(pfm_intel_x86_perf_validate_pattrs),
	.get_event_nattrs	= pfm_intel_x86_get_event_nattrs,
};
