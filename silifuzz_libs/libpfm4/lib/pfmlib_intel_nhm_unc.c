/*
 * pfmlib_intel_nhm_unc.c : Intel Nehalem/Westmere uncore PMU
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
 */
#include <sys/types.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* private headers */
#include "pfmlib_priv.h"
#include "pfmlib_intel_x86_priv.h"

#define NHM_UNC_ATTR_E	0
#define NHM_UNC_ATTR_I	1
#define NHM_UNC_ATTR_C	2
#define NHM_UNC_ATTR_O	3

#define _NHM_UNC_ATTR_I  (1 << NHM_UNC_ATTR_I)
#define _NHM_UNC_ATTR_E  (1 << NHM_UNC_ATTR_E)
#define _NHM_UNC_ATTR_C  (1 << NHM_UNC_ATTR_C)
#define _NHM_UNC_ATTR_O  (1 << NHM_UNC_ATTR_O)

#define NHM_UNC_ATTRS \
	(_NHM_UNC_ATTR_I|_NHM_UNC_ATTR_E|_NHM_UNC_ATTR_C|_NHM_UNC_ATTR_O)

#define NHM_UNC_MOD_OCC_BIT 	17
#define NHM_UNC_MOD_EDGE_BIT	18
#define NHM_UNC_MOD_INV_BIT	23
#define NHM_UNC_MOD_CMASK_BIT	24

#define NHM_UNC_MOD_OCC		(1 << NHM_UNC_MOD_OCC_BIT)
#define NHM_UNC_MOD_EDGE	(1 << NHM_UNC_MOD_EDGE_BIT)
#define NHM_UNC_MOD_INV		(1 << NHM_UNC_MOD_INV_BIT)

/* Intel Nehalem/Westmere uncore event table */
#include "events/intel_nhm_unc_events.h"
#include "events/intel_wsm_unc_events.h"

static const pfmlib_attr_desc_t nhm_unc_mods[]={
	PFM_ATTR_B("e", "edge level"),				/* edge */
	PFM_ATTR_B("i", "invert"),				/* invert */
	PFM_ATTR_I("c", "counter-mask in range [0-255]"),	/* counter-mask */
	PFM_ATTR_B("o", "queue occupancy"),			/* queue occupancy */
	PFM_ATTR_NULL
};

static const int nhm_models[] = {
	26,
	30,
	31,
	0
};

static const int wsm_dp_models[] = {
	44, /* Westmere-EP, Gulftown */
	47, /* Westmere E7 */
	0,
};

static int
pfm_nhm_unc_get_encoding(void *this, pfmlib_event_desc_t *e)
{
	pfm_intel_x86_reg_t reg;
	pfmlib_event_attr_info_t *a;
	const intel_x86_entry_t *pe = this_pe(this);
	unsigned int grpmsk, ugrpmsk = 0;
	int umodmsk = 0, modmsk_r = 0;
	uint64_t val;
	uint64_t umask;
	unsigned int modhw = 0;
	int k, ret, grpid, last_grpid = -1;
	int grpcounts[INTEL_X86_NUM_GRP];
	int ncombo[INTEL_X86_NUM_GRP];
	char umask_str[PFMLIB_EVT_MAX_NAME_LEN];

	memset(grpcounts, 0, sizeof(grpcounts));
	memset(ncombo, 0, sizeof(ncombo));

	umask_str[0] = e->fstr[0] = '\0';

	reg.val = 0;

	val = pe[e->event].code;

	grpmsk = (1 << pe[e->event].ngrp)-1;
	reg.val |= val; /* preset some filters from code */

	/* take into account hardcoded umask */
	umask = (val >> 8) & 0xff;

	modmsk_r = pe[e->event].modmsk_req;

	for(k=0; k < e->nattrs; k++) {
		a = attr(e, k);

		if (a->ctrl != PFM_ATTR_CTRL_PMU)
			continue;

		if (a->type == PFM_ATTR_UMASK) {
			grpid = pe[e->event].umasks[a->idx].grpid;

			/*
			 * cfor certain events groups are meant to be
			 * exclusive, i.e., only unit masks of one group
			 * can be used
			 */
			if (last_grpid != -1 && grpid != last_grpid
			    && intel_x86_eflag(this, e->event, INTEL_X86_GRP_EXCL)) {
				DPRINT("exclusive unit mask group error\n");
				return PFM_ERR_FEATCOMB;
			}
			/*
			 * upper layer has removed duplicates
			 * so if we come here more than once, it is for two
			 * disinct umasks
			 *
			 * NCOMBO=no combination of unit masks within the same
			 * umask group
			 */
			++grpcounts[grpid];

			if (intel_x86_uflag(this, e->event, a->idx, INTEL_X86_NCOMBO))
				ncombo[grpid] = 1;

			if (grpcounts[grpid] > 1 && ncombo[grpid])  {
				DPRINT("event does not support unit mask combination within a group\n");
				return PFM_ERR_FEATCOMB;
			}

			evt_strcat(umask_str, ":%s", pe[e->event].umasks[a->idx].uname);

			last_grpid = grpid;
			modhw    |= pe[e->event].umasks[a->idx].modhw;
			umask    |= pe[e->event].umasks[a->idx].ucode >> 8;
			ugrpmsk  |= 1 << pe[e->event].umasks[a->idx].grpid;

			reg.val |= umask << 8;

			modmsk_r |= pe[e->event].umasks[a->idx].umodmsk_req;

		} else if (a->type == PFM_ATTR_RAW_UMASK) {

			/* there can only be one RAW_UMASK per event */

			/* sanity check */
			if (a->idx & ~0xff) {
				DPRINT("raw umask is 8-bit wide\n");
				return PFM_ERR_ATTR;
			}
			/* override umask */
			umask = a->idx & 0xff;
			ugrpmsk = grpmsk;
		} else {
			uint64_t ival = e->attrs[k].ival;
			switch(a->idx) {
				case NHM_UNC_ATTR_I: /* invert */
					reg.nhm_unc.usel_inv = !!ival;
					umodmsk |= _NHM_UNC_ATTR_I;
					break;
				case NHM_UNC_ATTR_E: /* edge */
					reg.nhm_unc.usel_edge = !!ival;
					umodmsk |= _NHM_UNC_ATTR_E;
					break;
				case NHM_UNC_ATTR_C: /* counter-mask */
					/* already forced, cannot overwrite */
					if (ival > 255)
						return PFM_ERR_INVAL;
					reg.nhm_unc.usel_cnt_mask = ival;
					umodmsk |= _NHM_UNC_ATTR_C;
					break;
				case NHM_UNC_ATTR_O: /* occupancy */
					reg.nhm_unc.usel_occ = !!ival;
					umodmsk |= _NHM_UNC_ATTR_O;
					break;
			}
		}
	}

	if ((modhw & _NHM_UNC_ATTR_I) && reg.nhm_unc.usel_inv)
		return PFM_ERR_ATTR_SET;
	if ((modhw & _NHM_UNC_ATTR_E) && reg.nhm_unc.usel_edge)
		return PFM_ERR_ATTR_SET;
	if ((modhw & _NHM_UNC_ATTR_C) && reg.nhm_unc.usel_cnt_mask)
		return PFM_ERR_ATTR_SET;
	if ((modhw & _NHM_UNC_ATTR_O) && reg.nhm_unc.usel_occ)
		return PFM_ERR_ATTR_SET;

	/*
	 * check that there is at least of unit mask in each unit
	 * mask group
	 */
	if ((ugrpmsk != grpmsk && !intel_x86_eflag(this, e->event, INTEL_X86_GRP_EXCL)) || ugrpmsk == 0) {
		ugrpmsk ^= grpmsk;
		ret = pfm_intel_x86_add_defaults(this, e, ugrpmsk, &umask, (unsigned short) -1, -1);
		if (ret != PFM_SUCCESS)
			return ret;
	}

	if (modmsk_r && (umodmsk ^ modmsk_r)) {
		DPRINT("required modifiers missing: 0x%x\n", modmsk_r);
		return PFM_ERR_ATTR;
	}

	evt_strcat(e->fstr, "%s", pe[e->event].name);
	pfmlib_sort_attr(e);
	for(k=0; k < e->nattrs; k++) {
		a = attr(e, k);
		if (a->ctrl != PFM_ATTR_CTRL_PMU)
			continue;
		if (a->type == PFM_ATTR_UMASK)
			evt_strcat(e->fstr, ":%s", pe[e->event].umasks[a->idx].uname);
		else if (a->type == PFM_ATTR_RAW_UMASK)
			evt_strcat(e->fstr, ":0x%x", a->idx);
	}

	reg.val |= umask << 8;

	reg.nhm_unc.usel_en    = 1; /* force enable bit to 1 */
	reg.nhm_unc.usel_int   = 1; /* force APIC int to 1 */

	e->codes[0] = reg.val;
	e->count = 1;

	for (k = 0; k < e->npattrs; k++) {
		int idx;

		if (e->pattrs[k].ctrl != PFM_ATTR_CTRL_PMU)
			continue;

		if (e->pattrs[k].type == PFM_ATTR_UMASK)
			continue;

		idx = e->pattrs[k].idx;
		switch(idx) {
		case NHM_UNC_ATTR_E:
			evt_strcat(e->fstr, ":%s=%lu", nhm_unc_mods[idx].name, reg.nhm_unc.usel_edge);
			break;
		case NHM_UNC_ATTR_I:
			evt_strcat(e->fstr, ":%s=%lu", nhm_unc_mods[idx].name, reg.nhm_unc.usel_inv);
			break;
		case NHM_UNC_ATTR_C:
			evt_strcat(e->fstr, ":%s=%lu", nhm_unc_mods[idx].name, reg.nhm_unc.usel_cnt_mask);
			break;
		case NHM_UNC_ATTR_O:
			evt_strcat(e->fstr, ":%s=%lu", nhm_unc_mods[idx].name, reg.nhm_unc.usel_occ);
			break;
		}
	}
	__pfm_vbprintf("[UNC_PERFEVTSEL=0x%"PRIx64" event=0x%x umask=0x%x en=%d int=%d inv=%d edge=%d occ=%d cnt_msk=%d] %s\n",
		reg.val,
		reg.nhm_unc.usel_event,
		reg.nhm_unc.usel_umask,
		reg.nhm_unc.usel_en,
		reg.nhm_unc.usel_int,
		reg.nhm_unc.usel_inv,
		reg.nhm_unc.usel_edge,
		reg.nhm_unc.usel_occ,
		reg.nhm_unc.usel_cnt_mask,
		pe[e->event].name);

	return PFM_SUCCESS;
}

pfmlib_pmu_t intel_nhm_unc_support={
	.desc			= "Intel Nehalem uncore",
	.name			= "nhm_unc",
	.perf_name		= "uncore",

	.pmu			= PFM_PMU_INTEL_NHM_UNC,
	.pme_count		= LIBPFM_ARRAY_SIZE(intel_nhm_unc_pe),
	.type			= PFM_PMU_TYPE_UNCORE,
	.num_cntrs		= 8,
	.num_fixed_cntrs	= 1,
	.max_encoding		= 1,
	.pe			= intel_nhm_unc_pe,
	.atdesc			= nhm_unc_mods,
	.flags			= PFMLIB_PMU_FL_RAW_UMASK,

	.cpu_family		= 6,
	.cpu_models		= nhm_models,
	.pmu_detect		= pfm_intel_x86_model_detect,

	.get_event_encoding[PFM_OS_NONE] = pfm_nhm_unc_get_encoding,
	 PFMLIB_ENCODE_PERF(pfm_intel_nhm_unc_get_perf_encoding),

	.get_event_first	= pfm_intel_x86_get_event_first,
	.get_event_next		= pfm_intel_x86_get_event_next,
	.event_is_valid		= pfm_intel_x86_event_is_valid,
	.validate_table		= pfm_intel_x86_validate_table,
	.get_event_info		= pfm_intel_x86_get_event_info,
	.get_event_attr_info	= pfm_intel_x86_get_event_attr_info,
	PFMLIB_VALID_PERF_PATTRS(pfm_intel_x86_perf_validate_pattrs),
	.get_event_nattrs	= pfm_intel_x86_get_event_nattrs,
};

pfmlib_pmu_t intel_wsm_unc_support={
	.desc			= "Intel Westmere uncore",
	.name			= "wsm_unc",
	.perf_name		= "uncore",

	.pmu			= PFM_PMU_INTEL_WSM_UNC,
	.pme_count		= LIBPFM_ARRAY_SIZE(intel_wsm_unc_pe),
	.type			= PFM_PMU_TYPE_UNCORE,
	.num_cntrs		= 8,
	.num_fixed_cntrs	= 1,
	.max_encoding		= 1,
	.pe			= intel_wsm_unc_pe,
	.atdesc			= nhm_unc_mods,
	.flags			= PFMLIB_PMU_FL_RAW_UMASK,

	.cpu_family		= 6,
	.cpu_models		= wsm_dp_models,
	.pmu_detect		= pfm_intel_x86_model_detect,

	.get_event_encoding[PFM_OS_NONE] = pfm_nhm_unc_get_encoding,
	 PFMLIB_ENCODE_PERF(pfm_intel_nhm_unc_get_perf_encoding),

	.get_event_first	= pfm_intel_x86_get_event_first,
	.get_event_next		= pfm_intel_x86_get_event_next,
	.event_is_valid		= pfm_intel_x86_event_is_valid,
	.validate_table		= pfm_intel_x86_validate_table,
	.get_event_info		= pfm_intel_x86_get_event_info,
	.get_event_attr_info	= pfm_intel_x86_get_event_attr_info,
	PFMLIB_VALID_PERF_PATTRS(pfm_intel_x86_perf_validate_pattrs),
	.get_event_nattrs	= pfm_intel_x86_get_event_nattrs,
};
