/* pfmlib_intel_x86.c : common code for Intel X86 processors
 *
 * Copyright (c) 2009 Google, Inc
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
 * This file implements the common code for all Intel X86 processors.
 */
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

/* private headers */
#include "pfmlib_priv.h"
#include "pfmlib_intel_x86_priv.h"

const pfmlib_attr_desc_t intel_x86_mods[]={
	PFM_ATTR_B("k", "monitor at priv level 0"),		/* monitor priv level 0 */
	PFM_ATTR_B("u", "monitor at priv level 1, 2, 3"),	/* monitor priv level 1, 2, 3 */
	PFM_ATTR_B("e", "edge level (may require counter-mask >= 1)"), /* edge */
	PFM_ATTR_B("i", "invert"),				/* invert */
	PFM_ATTR_I("c", "counter-mask in range [0-255]"),	/* counter-mask */
	PFM_ATTR_B("t", "measure any thread"),			/* monitor on both threads */
	PFM_ATTR_I("ldlat", "load latency threshold (cycles, [3-65535])"),	/* load latency threshold */
	PFM_ATTR_B("intx", "monitor only inside transactional memory region"),
	PFM_ATTR_B("intxcp", "do not count occurrences inside aborted transactional memory region"),
	PFM_ATTR_I("fe_thres", "frontend bubble latency threshold in cycles ([1-4095]"),
	PFM_ATTR_NULL /* end-marker to avoid exporting number of entries */
};

pfm_intel_x86_config_t pfm_intel_x86_cfg;

#define mdhw(m, u, at) (m & u & _INTEL_X86_##at)

static inline void
cpuid(unsigned int op, unsigned int *a, unsigned int *b, unsigned int *c, unsigned int *d)
{
	asm volatile("cpuid" : "=a" (*a), "=b" (*b), "=c" (*c), "=d" (*d) : "a" (op) : "memory");
}

static void
pfm_intel_x86_display_reg(void *this, pfmlib_event_desc_t *e)
{
	const intel_x86_entry_t *pe = this_pe(this);
	pfm_intel_x86_reg_t reg;
	int i;

	reg.val = e->codes[0];

	/*
	 * handle generic counters
	 */
	__pfm_vbprintf("[0x%"PRIx64" event_sel=0x%x umask=0x%x os=%d usr=%d "
		       "en=%d int=%d inv=%d edge=%d cnt_mask=%d",
			reg.val,
			reg.sel_event_select,
			reg.sel_unit_mask,
			reg.sel_os,
			reg.sel_usr,
			reg.sel_en,
			reg.sel_int,
			reg.sel_inv,
			reg.sel_edge,
			reg.sel_cnt_mask);

	if (pe[e->event].modmsk & _INTEL_X86_ATTR_T)
		__pfm_vbprintf(" any=%d", reg.sel_anythr);

	__pfm_vbprintf("]");

	for (i = 1 ; i < e->count; i++)
		__pfm_vbprintf(" [0x%"PRIx64"]", e->codes[i]);

	__pfm_vbprintf(" %s\n", e->fstr);

}

/*
 * number of HW modifiers
 */
static int
intel_x86_num_mods(void *this, int idx)
{
	const intel_x86_entry_t *pe = this_pe(this);
	unsigned int mask;

	mask = pe[idx].modmsk;
	return pfmlib_popcnt(mask);
}

int
intel_x86_attr2mod(void *this, int pidx, int attr_idx)
{
	const intel_x86_entry_t *pe = this_pe(this);
	size_t x;
	int n, numasks;

	numasks = intel_x86_num_umasks(this, pidx);
	n = attr_idx - numasks;

	pfmlib_for_each_bit(x, pe[pidx].modmsk) {
		if (n == 0)
			break;
		n--;
	}
	return x;
}

/*
 * detect processor model using cpuid()
 * based on documentation
 * http://www.intel.com/Assets/PDF/appnote/241618.pdf
 */
int
pfm_intel_x86_detect(void)
{
	unsigned int a, b, c, d;
	char buffer[64];

	if (pfm_intel_x86_cfg.family)
		return PFM_SUCCESS;

	cpuid(0, &a, &b, &c, &d);
	strncpy(&buffer[0], (char *)(&b), 4);
	strncpy(&buffer[4], (char *)(&d), 4);
	strncpy(&buffer[8], (char *)(&c), 4);
	buffer[12] = '\0';

	/* must be Intel */
	if (strcmp(buffer, "GenuineIntel"))
		return PFM_ERR_NOTSUPP;

	cpuid(1, &a, &b, &c, &d);

	pfm_intel_x86_cfg.family = (a >> 8) & 0xf;  // bits 11 - 8
	pfm_intel_x86_cfg.model  = (a >> 4) & 0xf;  // Bits  7 - 4
	pfm_intel_x86_cfg.stepping = a & 0xf;	    // Bits 0 - 3

	/* extended family */
	if (pfm_intel_x86_cfg.family == 0xf)
		pfm_intel_x86_cfg.family += (a >> 20) & 0xff;

	/* extended model */
	if (pfm_intel_x86_cfg.family >= 0x6)
		pfm_intel_x86_cfg.model += ((a >> 16) & 0xf) << 4;

	return PFM_SUCCESS;
}

int pfm_intel_x86_model_detect(void *this)
{
	pfmlib_pmu_t *pmu = this;
	const int *p;
	int ret;

	ret = pfm_intel_x86_detect();
	if (ret != PFM_SUCCESS)
		return ret;

	if (pfm_intel_x86_cfg.family != pmu->cpu_family)
		return PFM_ERR_NOTSUPP;

	for (p = pmu->cpu_models; *p; p++) {
		if (*p == pfm_intel_x86_cfg.model)
			return PFM_SUCCESS;
	}
	return PFM_ERR_NOTSUPP;
}

int
pfm_intel_x86_add_defaults(void *this, pfmlib_event_desc_t *e,
			   unsigned int msk,
			   uint64_t *umask,
			   unsigned short max_grpid,
			   int excl_grp_but_0)
{
	const intel_x86_entry_t *pe = this_pe(this);
	const intel_x86_entry_t *ent;
	unsigned int i;
	unsigned short grpid;
	int j, k, added, skip;
	int idx;

	k = e->nattrs;
	ent = pe+e->event;

	for(i=0; msk; msk >>=1, i++) {

		if (!(msk & 0x1))
			continue;

		added = skip = 0;
		/*
		 * must scan list of possible attributes
		 * (not all possible attributes)
		 */
		for (j = 0; j < e->npattrs; j++) {
			if (e->pattrs[j].ctrl != PFM_ATTR_CTRL_PMU)
				continue;

			if (e->pattrs[j].type != PFM_ATTR_UMASK)
				continue;

			idx = e->pattrs[j].idx;

			if (get_grpid(ent->umasks[idx].grpid) != i)
				continue;

			if (max_grpid != INTEL_X86_MAX_GRPID && i > max_grpid) {
				skip = 1;
				continue;
			}

			if (intel_x86_uflag(this, e->event, idx, INTEL_X86_GRP_DFL_NONE)) {
				skip = 1;
				continue;
			}
			grpid = ent->umasks[idx].grpid;

			if (excl_grp_but_0  != -1 && grpid != 0  && excl_grp_but_0 != grpid) {
				skip = 1;
				continue;
			}

			/* umask is default for group */
			if (intel_x86_uflag(this, e->event, idx, INTEL_X86_DFL)) {
				DPRINT("added default %s for group %d j=%d idx=%d ucode=0x%"PRIx64"\n",
					ent->umasks[idx].uname,
					i,	
					j,
					idx,
					ent->umasks[idx].ucode);
				/*
				 * default could be an alias, but
				 * ucode must reflect actual code
				 */
				*umask |= ent->umasks[idx].ucode >> 8;

				e->attrs[k].id = j; /* pattrs index */
				e->attrs[k].ival = 0;
				k++;

				added++;
				if (intel_x86_eflag(this, e->event, INTEL_X86_GRP_EXCL))
					goto done;

				if (intel_x86_uflag(this, e->event, idx, INTEL_X86_EXCL_GRP_GT)) {
					if (max_grpid != INTEL_X86_MAX_GRPID) {
						DPRINT("two max_grpid, old=%d new=%d\n", max_grpid, get_grpid(ent->umasks[idx].grpid));
						return PFM_ERR_UMASK;
					}
					max_grpid = ent->umasks[idx].grpid;
				}
			}
		}
		if (!added && !skip) {
			DPRINT("no default found for event %s unit mask group %d (max_grpid=%d)\n", ent->name, i, max_grpid);
			return PFM_ERR_UMASK;
		}
	}
	DPRINT("max_grpid=%d nattrs=%d k=%d umask=0x%"PRIx64"\n", max_grpid, e->nattrs, k, *umask);
done:
	e->nattrs = k;
	return PFM_SUCCESS;
}

#if 1
static int
intel_x86_check_pebs(void *this, pfmlib_event_desc_t *e)
{
	return PFM_SUCCESS;
}
#else
/* this routine is supposed to check that umask combination is valid
 * w.r.t. PEBS. You cannot combine PEBS with non PEBS. But this is
 * only a problem is PEBS is requested. But this is not known at this
 * arch level. It is known at the OS interface level. Therefore we
 * cannot really check this here.
 * We keep the code around in case we need it later on
 */
static int
intel_x86_check_pebs(void *this, pfmlib_event_desc_t *e)
{
	const intel_x86_entry_t *pe = this_pe(this);
	pfmlib_event_attr_info_t *a;
	int numasks = 0, pebs = 0;
	int i;

	/*
	 * if event has no umask and is PEBS, then we are okay
	 */
	if (!pe[e->event].numasks
	    && intel_x86_eflag(this, e->event, INTEL_X86_PEBS))
		return PFM_SUCCESS;

	/*
	 * if the event sets PEBS, then it means at least one umask
	 * supports PEBS, so we need to check
	 */
	for (i = 0; i < e->nattrs; i++) {
		a = attr(e, i);

		if (a->ctrl != PFM_ATTR_CTRL_PMU)
			continue;

		if (a->type == PFM_ATTR_UMASK) {
			/* count number of umasks */
			numasks++;
			/* and those that support PEBS */
			if (intel_x86_uflag(this, e->event, a->idx, INTEL_X86_PEBS))
				pebs++;
		}
	}
	/*
	 * pass if user requested only PEBS  umasks
	 */
	return pebs != numasks ? PFM_ERR_FEATCOMB : PFM_SUCCESS;
}
#endif

static int
intel_x86_check_max_grpid(void *this, pfmlib_event_desc_t *e, unsigned short max_grpid)
{
	const intel_x86_entry_t *pe;
	pfmlib_event_attr_info_t *a;
	unsigned short grpid;
	int i;

	DPRINT("check: max_grpid=%d\n", max_grpid);
	pe = this_pe(this);

	for (i = 0; i < e->nattrs; i++) {
		a = attr(e, i);

		if (a->ctrl != PFM_ATTR_CTRL_PMU)
			continue;

		if (a->type == PFM_ATTR_UMASK) {
			grpid = pe[e->event].umasks[a->idx].grpid;
			if (grpid > max_grpid)
				return PFM_ERR_FEATCOMB;
		}
	}
	return PFM_SUCCESS;
}

static int
pfm_intel_x86_encode_gen(void *this, pfmlib_event_desc_t *e)

{
	pfmlib_pmu_t *pmu = this;
	pfmlib_event_attr_info_t *a;
	const intel_x86_entry_t *pe;
	pfm_intel_x86_reg_t reg, reg2;
	unsigned int grpmsk, ugrpmsk = 0;
	uint64_t umask1, umask2, ucode, last_ucode = ~0ULL;
	unsigned int modhw = 0;
	unsigned int plmmsk = 0;
	int umodmsk = 0, modmsk_r = 0;
	int k, ret, id;
	int max_req_grpid = -1;
	unsigned short grpid;
	unsigned short max_grpid = INTEL_X86_MAX_GRPID;
	unsigned short last_grpid =  INTEL_X86_MAX_GRPID;
	unsigned short req_grpid;
	unsigned int ldlat = 0, ldlat_um = 0;
	unsigned int fe_thr= 0, fe_thr_um = 0;
	int excl_grp_but_0 = -1;
	int grpcounts[INTEL_X86_NUM_GRP];
	int req_grps[INTEL_X86_NUM_GRP];
	int ncombo[INTEL_X86_NUM_GRP];

	memset(grpcounts, 0, sizeof(grpcounts));
	memset(ncombo, 0, sizeof(ncombo));

	pe     = this_pe(this);

	e->fstr[0] = '\0';

	/*
	 * preset certain fields from event code
	 * including modifiers
	 */
	reg.val = pe[e->event].code;

	grpmsk = (1 << pe[e->event].ngrp)-1;

	/* take into account hardcoded umask */
	umask1 = (reg.val >> 8) & 0xff;
	umask2 = 0;

	modmsk_r = pe[e->event].modmsk_req;

	for (k = 0; k < e->nattrs; k++) {
		a = attr(e, k);

		if (a->ctrl != PFM_ATTR_CTRL_PMU)
			continue;

		if (a->type == PFM_ATTR_UMASK) {
			grpid     = get_grpid(pe[e->event].umasks[a->idx].grpid);
			req_grpid = get_req_grpid(pe[e->event].umasks[a->idx].grpid);

			/*
			 * certain event groups are meant to be
			 * exclusive, i.e., only unit masks of one group
			 * can be used
			 */
			if (last_grpid != INTEL_X86_MAX_GRPID && grpid != last_grpid
			    && intel_x86_eflag(this, e->event, INTEL_X86_GRP_EXCL)) {
				DPRINT("exclusive unit mask group error\n");
				return PFM_ERR_FEATCOMB;
			}
			/*
			 * selecting certain umasks in a group may exclude any umasks
			 * from any groups with a higher index
			 *
			 * enforcement requires looking at the grpid of all the umasks
			 */
			if (intel_x86_uflag(this, e->event, a->idx, INTEL_X86_EXCL_GRP_GT))
				max_grpid = grpid;

			if (intel_x86_uflag(this, e->event, a->idx, INTEL_X86_EXCL_GRP_BUT_0))
				excl_grp_but_0 = grpid;
			/*
			 * upper layer has removed duplicates
			 * so if we come here more than once, it is for two
			 * disinct umasks
			 *
			 * NCOMBO=no combination of unit masks within the same
			 * umask group
			 */
			++grpcounts[grpid];
			if (intel_x86_uflag(this, e->event, a->idx, INTEL_X86_GRP_REQ)) {
				DPRINT("event requires grpid %d\n", req_grpid);
				/* initialize req_grpcounts array only when needed */
				if (max_req_grpid == -1) {
					int x;
					for (x = 0; x < INTEL_X86_NUM_GRP; x++)
						req_grps[x] = 0xff;
				}
				if (req_grpid > max_req_grpid)
					max_req_grpid = req_grpid;
				DPRINT("max_req_grpid=%d\n", max_req_grpid);
				req_grps[req_grpid] = 1;
			}

			/* mark that we have a umask with NCOMBO in this group */
			if (intel_x86_uflag(this, e->event, a->idx, INTEL_X86_NCOMBO))
				ncombo[grpid] = 1;

			if (intel_x86_uflag(this, e->event, a->idx, INTEL_X86_LDLAT))
				ldlat_um = 1;

			if (intel_x86_uflag(this, e->event, a->idx, INTEL_X86_FETHR))
				fe_thr_um = 1;

			/*
			 * if more than one umask in this group but one is marked
			 * with ncombo, then fail. It is okay to combine umask within
			 * a group as long as none is tagged with NCOMBO
			 */
			if (grpcounts[grpid] > 1 && ncombo[grpid])  {
				DPRINT("umask %s does not support unit mask combination within group %d\n", pe[e->event].umasks[a->idx].uname, grpid);
				return PFM_ERR_FEATCOMB;
			}

			last_grpid= grpid;
			ucode     = pe[e->event].umasks[a->idx].ucode;
			modhw    |= pe[e->event].umasks[a->idx].modhw;
			umask2   |= ucode >> 8;
			ugrpmsk  |= 1 << pe[e->event].umasks[a->idx].grpid;

			modmsk_r |= pe[e->event].umasks[a->idx].umodmsk_req;

			if (intel_x86_uflag(this, e->event, a->idx, INTEL_X86_CODE_OVERRIDE)) {
				if (last_ucode != ~0ULL && (ucode & 0xff) != last_ucode) {
					DPRINT("cannot override event with two different codes for %s\n", pe[e->event].name);
					return PFM_ERR_FEATCOMB;
				}
				last_ucode = ucode & 0xff;
				reg.sel_event_select = last_ucode;
			}
		} else if (a->type == PFM_ATTR_RAW_UMASK) {
			int ofr_bits = 8;
			uint64_t rmask;

			/* set limit on width of raw umask */
			if (intel_x86_eflag(this, e->event, INTEL_X86_NHM_OFFCORE)) {
				ofr_bits = 38;
				if (e->pmu->pmu == PFM_PMU_INTEL_WSM || e->pmu->pmu == PFM_PMU_INTEL_WSM_DP)
					ofr_bits = 16;
			}
			rmask = (1ULL << ofr_bits) - 1;

			if (a->idx & ~rmask) {
				DPRINT("raw umask is too wide max %d bits\n", ofr_bits);
				return PFM_ERR_ATTR;
			}

			/* override umask */
			umask2  = a->idx & rmask;
			ugrpmsk = grpmsk;
		} else {
			uint64_t ival = e->attrs[k].ival;
			switch(a->idx) {
				case INTEL_X86_ATTR_I: /* invert */
					reg.sel_inv = !!ival;
					umodmsk |= _INTEL_X86_ATTR_I;
					break;
				case INTEL_X86_ATTR_E: /* edge */
					reg.sel_edge = !!ival;
					umodmsk |= _INTEL_X86_ATTR_E;
					break;
				case INTEL_X86_ATTR_C: /* counter-mask */
					if (ival > 255)
						return PFM_ERR_ATTR_VAL;
					reg.sel_cnt_mask = ival;
					umodmsk |= _INTEL_X86_ATTR_C;
					break;
				case INTEL_X86_ATTR_U: /* USR */
					reg.sel_usr = !!ival;
					plmmsk |= _INTEL_X86_ATTR_U;
					umodmsk |= _INTEL_X86_ATTR_U;
					break;
				case INTEL_X86_ATTR_K: /* OS */
					reg.sel_os = !!ival;
					plmmsk |= _INTEL_X86_ATTR_K;
					umodmsk |= _INTEL_X86_ATTR_K;
					break;
				case INTEL_X86_ATTR_T: /* anythread (v3 and above) */
					reg.sel_anythr = !!ival;
					umodmsk |= _INTEL_X86_ATTR_T;
					break;
				case INTEL_X86_ATTR_LDLAT: /* load latency */
					/* as per Intel SDM, lowest value is 1, 16-bit field */
					if (ival < 1 || ival > 65535)
						return PFM_ERR_ATTR_VAL;
					ldlat = ival;
					break;
				case INTEL_X86_ATTR_INTX: /* in_tx */
					reg.sel_intx = !!ival;
					umodmsk |= _INTEL_X86_ATTR_INTX;
					break;
				case INTEL_X86_ATTR_INTXCP: /* in_tx_cp */
					reg.sel_intxcp = !!ival;
					umodmsk |= _INTEL_X86_ATTR_INTXCP;
					break;
				case INTEL_X86_ATTR_FETHR: /* precise frontend latency threshold */
					if (ival < 1 || ival > 4095)
						return PFM_ERR_ATTR_VAL;
					fe_thr = ival;
					umodmsk |= _INTEL_X86_ATTR_FETHR;
					break;
			}
		}
	}
	/* check required groups are in place */
	if (max_req_grpid != -1) {
		int x;
		for (x = 0; x <= max_req_grpid; x++) {
			if (req_grps[x] == 0xff)
				continue;
			if ((ugrpmsk & (1 << x)) == 0) {
				DPRINT("required grpid %d umask missing\n", x);
				return PFM_ERR_FEATCOMB;
			}
		}
	}

	/*
	 * we need to wait until all the attributes have been parsed to check
	 * for conflicts between hardcoded attributes and user-provided attributes.
	 * we do not want to depend on the order in which they are specified
	 *
	 * The test check for conflicts. It is okay to specify an attribute if
	 * it encodes to the same same value as the hardcoded value. That allows
	 * use to prase a FQESTR (fully-qualified event string) as returned by
	 * the library
	 */
	reg2.val = (umask1 | umask2)  << 8;
	if (mdhw(modhw, umodmsk, ATTR_I) && reg2.sel_inv != reg.sel_inv)
		return PFM_ERR_ATTR_SET;
	if (mdhw(modhw, umodmsk, ATTR_E) && reg2.sel_edge != reg.sel_edge)
		return PFM_ERR_ATTR_SET;
	if (mdhw(modhw, umodmsk, ATTR_C) && reg2.sel_cnt_mask != reg.sel_cnt_mask)
		return PFM_ERR_ATTR_SET;
	if (mdhw(modhw, umodmsk, ATTR_U) && reg2.sel_usr != reg.sel_usr)
		return PFM_ERR_ATTR_SET;
	if (mdhw(modhw, umodmsk, ATTR_K) && reg2.sel_os != reg.sel_os)
		return PFM_ERR_ATTR_SET;
	if (mdhw(modhw, umodmsk, ATTR_T) && reg2.sel_anythr != reg.sel_anythr)
		return PFM_ERR_ATTR_SET;
	if (mdhw(modhw, umodmsk, ATTR_INTX) && reg2.sel_intx != reg.sel_intx)
		return PFM_ERR_ATTR_SET;
	if (mdhw(modhw, umodmsk, ATTR_INTXCP) && reg2.sel_intxcp != reg.sel_intxcp)
		return PFM_ERR_ATTR_SET;

	/*
	 * handle case where no priv level mask was passed.
	 * then we use the dfl_plm
	 */
	if (!(plmmsk & (_INTEL_X86_ATTR_K|_INTEL_X86_ATTR_U))) {
		if ((e->dfl_plm & PFM_PLM0) && (pmu->supported_plm & PFM_PLM0))
			reg.sel_os = 1;
		if ((e->dfl_plm & PFM_PLM3) && (pmu->supported_plm & PFM_PLM3))
			reg.sel_usr = 1;
	}
	/*
	 * check that there is at least of unit mask in each unit
	 * mask group
	 */
	if ((ugrpmsk != grpmsk && !intel_x86_eflag(this, e->event, INTEL_X86_GRP_EXCL)) || ugrpmsk == 0) {
		ugrpmsk ^= grpmsk;
		ret = pfm_intel_x86_add_defaults(this, e, ugrpmsk, &umask2, max_grpid, excl_grp_but_0);
		if (ret != PFM_SUCCESS)
			return ret;
	}
	/*
	 * GRP_EXCL_BUT_0 groups require at least one bit set in grpid = 0 and one in theirs
	 * applies to OFFCORE_RESPONSE umasks on some processors (e.g., Goldmont)
	 */
	DPRINT("excl_grp_but_0=%d\n", excl_grp_but_0);
	if (excl_grp_but_0 != -1) {
		/* skip group 0, because it is authorized */
		for (k = 1; k < INTEL_X86_NUM_GRP; k++) {
			DPRINT("grpcounts[%d]=%d\n", k, grpcounts[k]);
			if (grpcounts[k] && k != excl_grp_but_0) {
				DPRINT("GRP_EXCL_BUT_0 but grpcounts[%d]=%d\n", k, grpcounts[k]);
				return PFM_ERR_FEATCOMB;
			}
		}
	}
	ret = intel_x86_check_pebs(this, e);
	if (ret != PFM_SUCCESS)
		return ret;

	/*
	 * check no umask violates the max_grpid constraint
	 */
	if (max_grpid != INTEL_X86_MAX_GRPID) {
		ret = intel_x86_check_max_grpid(this, e, max_grpid);
		if (ret != PFM_SUCCESS) {
			DPRINT("event %s: umask from grp > %d\n", pe[e->event].name, max_grpid);
			return ret;
		}
	}

	if (modmsk_r && (umodmsk ^ modmsk_r)) {
		DPRINT("required modifiers missing: 0x%x\n", modmsk_r);
		return PFM_ERR_ATTR;
	}
	/*
	 * reorder all the attributes such that the fstr appears always
	 * the same regardless of how the attributes were submitted.
	 */
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

	if (intel_x86_eflag(this, e->event, INTEL_X86_FRONTEND)) {
		uint64_t um_thr = (umask2 >> 8) & 0xfff; /* threshold from umask */

		DPRINT("um_thr=0x%"PRIx64 " fe_thr=%u thr_um=%u modhw=0x%x umodhw=0x%x\n", um_thr, fe_thr, fe_thr_um, modhw, umodmsk);
		/* umask expects a fe_thres modifier */
		if (fe_thr_um) {
			/* hardware has non zero fe_thres (hardcoded) */
			if (um_thr) {
				/* user passed fe_thres, then must match hardcoded */
				if (mdhw(modhw, umodmsk, ATTR_FETHR)) {
					if (fe_thr != um_thr)
						return PFM_ERR_ATTR_SET;
				} else
					fe_thr = um_thr;
			} else if (fe_thr == 0) {
				fe_thr = INTEL_X86_FETHR_DEFAULT;
			}
			umask2 &= ~((0xfffULL) << 8);
			umask2 |= fe_thr << 8;
		}
	}

	/*
	 * offcore_response or precise frontend require a separate register
	 */
	if (intel_x86_eflag(this, e->event, INTEL_X86_NHM_OFFCORE)
	    || intel_x86_eflag(this, e->event, INTEL_X86_FRONTEND)) {
		e->codes[1] = umask2;
		e->count = 2;
		umask2 = 0;
	} else {
		e->count = 1;
	}

	if (ldlat && !ldlat_um) {
		DPRINT("passed ldlat= but not using ldlat umask\n");
		return PFM_ERR_ATTR;
	}

	/*
	 * force a default ldlat (will not appear in display_reg)
	 */
	if (ldlat_um && !ldlat) {
		DPRINT("missing ldlat= for umask, forcing to default %d cycles\n", INTEL_X86_LDLAT_DEFAULT);
		ldlat = INTEL_X86_LDLAT_DEFAULT;
	}

	if (ldlat && ldlat_um) {
		e->codes[1] = ldlat;
		e->count = 2;
	}

	/* take into account hardcoded modifiers, so use or on reg.val */
	reg.val     |= (umask1 | umask2)  << 8;

	reg.sel_en   = 1; /* force enable bit to 1 */
	reg.sel_int  = 1; /* force APIC int to 1 */

	e->codes[0] = reg.val;

	/*
	 * on recent processors (except Atom), edge requires cmask >=1
	 */
	if ((pmu->flags & INTEL_X86_PMU_FL_ECMASK)
	    && reg.sel_edge && !reg.sel_cnt_mask) {
		DPRINT("edge requires cmask >= 1\n");
		return PFM_ERR_ATTR;
	}

	/*
	 * decode ALL modifiers
	 */
	for (k = 0; k < e->npattrs; k++) {
		if (e->pattrs[k].ctrl != PFM_ATTR_CTRL_PMU)
			continue;

		if (e->pattrs[k].type == PFM_ATTR_UMASK)
			continue;

		id = e->pattrs[k].idx;
		switch(id) {
		case INTEL_X86_ATTR_U:
			evt_strcat(e->fstr, ":%s=%lu", intel_x86_mods[id].name, reg.sel_usr);
			break;
		case INTEL_X86_ATTR_K:
			evt_strcat(e->fstr, ":%s=%lu", intel_x86_mods[id].name, reg.sel_os);
			break;
		case INTEL_X86_ATTR_E:
			evt_strcat(e->fstr, ":%s=%lu", intel_x86_mods[id].name, reg.sel_edge);
			break;
		case INTEL_X86_ATTR_I:
			evt_strcat(e->fstr, ":%s=%lu", intel_x86_mods[id].name, reg.sel_inv);
			break;
		case INTEL_X86_ATTR_C:
			evt_strcat(e->fstr, ":%s=%lu", intel_x86_mods[id].name, reg.sel_cnt_mask);
			break;
		case INTEL_X86_ATTR_T:
			evt_strcat(e->fstr, ":%s=%lu", intel_x86_mods[id].name, reg.sel_anythr);
			break;
		case INTEL_X86_ATTR_LDLAT:
			evt_strcat(e->fstr, ":%s=%d", intel_x86_mods[id].name, ldlat);
			break;
		case INTEL_X86_ATTR_INTX:
			evt_strcat(e->fstr, ":%s=%lu", intel_x86_mods[id].name, reg.sel_intx);
			break;
		case INTEL_X86_ATTR_INTXCP:
			evt_strcat(e->fstr, ":%s=%lu", intel_x86_mods[id].name, reg.sel_intxcp);
			break;
		case INTEL_X86_ATTR_FETHR:
			evt_strcat(e->fstr, ":%s=%lu", intel_x86_mods[id].name, fe_thr);
			break;
		}
	}
	return PFM_SUCCESS;
}

int
pfm_intel_x86_get_encoding(void *this, pfmlib_event_desc_t *e)
{
	int ret;

	ret = pfm_intel_x86_encode_gen(this, e);
	if (ret != PFM_SUCCESS)
		return ret;

	pfm_intel_x86_display_reg(this, e);

	return PFM_SUCCESS;
}

int
pfm_intel_x86_get_event_first(void *this)
{
	pfmlib_pmu_t *p = this;
	int idx = 0;

	/* skip event for different models */
	while (idx < p->pme_count && !is_model_event(this, idx)) idx++;

	return idx < p->pme_count ? idx : -1;
}

int
pfm_intel_x86_get_event_next(void *this, int idx)
{
	pfmlib_pmu_t *p = this;

	/* pme_count is always >= 1*/
	if (idx >= (p->pme_count-1))
		return -1;

	idx++;
	/* skip event for different models */
	while (idx < p->pme_count && !is_model_event(this, idx)) idx++;

	return idx < p->pme_count ? idx : -1;
}

int
pfm_intel_x86_event_is_valid(void *this, int pidx)
{
	pfmlib_pmu_t *p = this;
	return pidx >= 0 && pidx < p->pme_count && is_model_event(this, pidx);
}

int
pfm_intel_x86_validate_table(void *this, FILE *fp)
{
	pfmlib_pmu_t *pmu = this;
	const intel_x86_entry_t *pe = this_pe(this);
	int ndfl[INTEL_X86_NUM_GRP];
	int i, j, error = 0;
	unsigned int u, v;
	int npebs;

	if (!pmu->atdesc) {
		fprintf(fp, "pmu: %s missing attr_desc\n", pmu->name);
		error++;
	}

	if (!pmu->supported_plm && pmu->type == PFM_PMU_TYPE_CORE) {
		fprintf(fp, "pmu: %s supported_plm not set\n", pmu->name);
		error++;
	}

	for(i=0; i < pmu->pme_count; i++) {

		if (!is_model_event(this, i))
			continue;

		if (!pe[i].name) {
			fprintf(fp, "pmu: %s event%d: :: no name (prev event was %s)\n", pmu->name, i,
			i > 1 ? pe[i-1].name : "??");
			error++;
		}

		if (!pe[i].desc) {
			fprintf(fp, "pmu: %s event%d: %s :: no description\n", pmu->name, i, pe[i].name);
			error++;
		}
		if (pe[i].desc && strlen(pe[i].desc) == 0) {
			fprintf(fp, "pmu: %s event%d: %s :: empty description\n", pmu->name, i, pe[i].name);
			error++;
		}
		if (!pe[i].cntmsk) {
			fprintf(fp, "pmu: %s event%d: %s :: cntmsk=0\n", pmu->name, i, pe[i].name);
			error++;
		}

		if (pe[i].numasks && pe[i].ngrp == 0) {
			fprintf(fp, "pmu: %s event%d: %s :: ngrp cannot be zero\n", pmu->name, i, pe[i].name);
			error++;
		}

		if (pe[i].numasks && pe[i].umasks == NULL) {
			fprintf(fp, "pmu: %s event%d: %s :: numasks but no umasks\n", pmu->name, i, pe[i].name);
			error++;
		}

		if (pe[i].numasks == 0 && pe[i].umasks) {
			fprintf(fp, "pmu: %s event%d: %s :: numasks=0 but umasks defined\n", pmu->name, i, pe[i].name);
			error++;
		}

		if (pe[i].numasks == 0 && pe[i].ngrp) {
			fprintf(fp, "pmu: %s event%d: %s :: ngrp must be zero\n", pmu->name, i, pe[i].name);
			error++;
		}

		if (pe[i].ngrp >= INTEL_X86_NUM_GRP) {
			fprintf(fp, "pmu: %s event%d: %s :: ngrp too big (max=%d)\n", pmu->name, i, pe[i].name, INTEL_X86_NUM_GRP);
			error++;
		}
		if (pe[i].model >= PFM_PMU_MAX) {
			fprintf(fp, "pmu: %s event%d: %s :: model too big (max=%d)\n", pmu->name, i, pe[i].name, PFM_PMU_MAX);
			error++;
		}

		for (j=i+1; j < (int)pmu->pme_count; j++) {
			if (pe[i].code == pe[j].code && pe[i].model == pe[j].model && !intel_x86_eflag(pmu, i, INTEL_X86_DEPRECATED) && !(pe[j].equiv || pe[i].equiv) && pe[j].cntmsk == pe[i].cntmsk && !intel_x86_eflag(pmu, i, INTEL_X86_CODE_DUP) && !!intel_x86_eflag(pmu, j, INTEL_X86_CODE_DUP))  {
				fprintf(fp, "pmu: %s events %s and %s have the same code 0x%x\n", pmu->name, pe[i].name, pe[j].name, pe[i].code);
				error++;
				}
			}

		for(j=0; j < INTEL_X86_NUM_GRP; j++)
			ndfl[j] = 0;

		for(j=0, npebs = 0; j < (int)pe[i].numasks; j++) {

			if (!pe[i].umasks[j].uname) {
				fprintf(fp, "pmu: %s event%d: %s umask%d :: no name\n", pmu->name, i, pe[i].name, j);
				error++;
			}
			if (pe[i].umasks[j].modhw && (pe[i].umasks[j].modhw | pe[i].modmsk) != pe[i].modmsk) {
				fprintf(fp, "pmu: %s event%d: %s umask%d: %s :: modhw not subset of modmsk\n", pmu->name, i, pe[i].name, j, pe[i].umasks[j].uname);
				error++;
			}

			if (!pe[i].umasks[j].udesc) {
				fprintf(fp, "pmu: %s event%d: umask%d: %s :: no description\n", pmu->name, i, j, pe[i].umasks[j].uname);
				error++;
			}
			if (pe[i].umasks[j].udesc && strlen(pe[i].umasks[j].udesc) == 0) {
				fprintf(fp, "pmu: %s event%d: umask%d: %s :: empty description\n", pmu->name, i, j, pe[i].umasks[j].uname);
				error++;
			}
			if (pe[i].ngrp && get_grpid(pe[i].umasks[j].grpid) >= pe[i].ngrp) {
				fprintf(fp, "pmu: %s event%d: %s umask%d: %s :: invalid grpid %d (must be < %d)\n", pmu->name, i, pe[i].name, j, pe[i].umasks[j].uname, get_grpid(pe[i].umasks[j].grpid), pe[i].ngrp);
				error++;
			}
			if (pe[i].ngrp && get_req_grpid(pe[i].umasks[j].grpid) >= pe[i].ngrp) {
				fprintf(fp, "pmu: %s event%d: %s umask%d: %s :: invalid req_grpid %d (must be < %d)\n", pmu->name, i, pe[i].name, j, pe[i].umasks[j].uname, get_req_grpid(pe[i].umasks[j].grpid), pe[i].ngrp);
				error++;
			}
				if (pe[i].umasks[j].umodel >= PFM_PMU_MAX) {
				fprintf(fp, "pmu: %s event%d: %s umask%d: %s :: model too big (max=%d)\n", pmu->name, i, pe[i].name,  j, pe[i].umasks[j].uname, PFM_PMU_MAX);
				error++;
			}
			if (pe[i].umasks[j].uflags & INTEL_X86_DFL)
				ndfl[pe[i].umasks[j].grpid]++;

			if (pe[i].umasks[j].uflags & INTEL_X86_PEBS)
				npebs++;
		}

		if (npebs && !intel_x86_eflag(this, i, INTEL_X86_PEBS)) {
			fprintf(fp, "pmu: %s event%d: %s, pebs umasks but event pebs flag is not set\n", pmu->name, i, pe[i].name);
			error++;
		}

		if (intel_x86_eflag(this, i, INTEL_X86_PEBS) && pe[i].numasks && npebs == 0) {
			fprintf(fp, "pmu: %s event%d: %s, pebs event flag but no umask has the pebs flag\n", pmu->name, i, pe[i].name);
			error++;
		}

		/* if only one umask, then ought to be default */
		if (pe[i].numasks == 1 && !(pe[i].umasks[0].uflags & INTEL_X86_DFL)) {
			fprintf(fp, "pmu: %s event%d: %s, only one umask but no default set\n", pmu->name, i, pe[i].name);
			error++;
		}

		if (pe[i].numasks) {
			unsigned int *dfl_model = malloc(sizeof(*dfl_model) * pe[i].numasks);
			if (!dfl_model)
				goto skip_dfl;
			for(u=0; u < pe[i].ngrp; u++) {
				int l = 0, m;
				for (v = 0; v < pe[i].numasks; v++) {
					if (pe[i].umasks[v].grpid != u)
						continue;
					if (pe[i].umasks[v].uflags & INTEL_X86_DFL) {
						for (m = 0; m < l; m++) {
							if (dfl_model[m] == pe[i].umasks[v].umodel || dfl_model[m] == 0) {
								fprintf(fp, "pmu: %s event%d: %s grpid %d has 2 default umasks\n", pmu->name, i, pe[i].name, u);
								error++;
							}
						}
						if (m == l)
							dfl_model[l++] = pe[i].umasks[v].umodel;
					}
				}
			}
			free(dfl_model);
		}
skip_dfl:

		if (pe[i].flags & INTEL_X86_NCOMBO) {
			fprintf(fp, "pmu: %s event%d: %s :: NCOMBO is a umask only flag\n", pmu->name, i, pe[i].name);
			error++;
		}

		for(u=0; u < pe[i].numasks; u++) {

			if (pe[i].umasks[u].uequiv)
				continue;

			if (pe[i].umasks[u].uflags & INTEL_X86_NCOMBO)
				continue;

			for(v=j+1; v < pe[i].numasks; v++) {
				if (pe[i].umasks[v].uequiv)
					continue;
				if (pe[i].umasks[v].uflags & INTEL_X86_NCOMBO)
					continue;
				if (pe[i].umasks[v].grpid != pe[i].umasks[u].grpid)
					continue;
				if ((pe[i].umasks[u].ucode & pe[i].umasks[v].ucode) && pe[i].umasks[u].umodel == pe[i].umasks[v].umodel) {
					fprintf(fp, "pmu: %s event%d: %s :: umask %s and %s have overlapping code bits\n", pmu->name, i, pe[i].name, pe[i].umasks[u].uname, pe[i].umasks[v].uname);
					error++;
				}
			}
		}
	}
	return error ? PFM_ERR_INVAL : PFM_SUCCESS;
}

int
pfm_intel_x86_get_event_attr_info(void *this, int pidx, int attr_idx, pfmlib_event_attr_info_t *info)
{
	const intel_x86_entry_t *pe = this_pe(this);
	const pfmlib_attr_desc_t *atdesc = this_atdesc(this);
	pfmlib_pmu_t *pmu = this;
	int numasks, idx;

	if (!is_model_event(this, pidx)) {
		DPRINT("invalid event index %d\n", pidx);
		return PFM_ERR_INVAL;
	}

	numasks = intel_x86_num_umasks(this, pidx);
	if (attr_idx < numasks) {
		int has_extpebs = pmu->flags & INTEL_X86_PMU_FL_EXTPEBS;

		idx = intel_x86_attr2umask(this, pidx, attr_idx);
		info->name = pe[pidx].umasks[idx].uname;
		info->desc = pe[pidx].umasks[idx].udesc;
		info->equiv= pe[pidx].umasks[idx].uequiv;

		info->code = pe[pidx].umasks[idx].ucode;
		if (!intel_x86_uflag(this, pidx, idx, INTEL_X86_CODE_OVERRIDE))
			info->code >>= 8;

		info->type = PFM_ATTR_UMASK;
		info->is_dfl = intel_x86_uflag(this, pidx, idx, INTEL_X86_DFL);
		info->is_precise = intel_x86_uflag(this, pidx, idx, INTEL_X86_PEBS);
		/*
		 * if PEBS is supported, then hw buffer sampling is also supported
		 * because PEBS is a hw buffer
		 */
		info->support_hw_smpl = (info->is_precise || has_extpebs);
		/*
		 * On Intel X86, either all or none of the umasks are speculative
		 * for a speculative event, so propagate speculation info to all
		 * umasks
		 */
		if (pmu->flags & PFMLIB_PMU_FL_SPEC) {
			int ret = intel_x86_eflag(this, pidx, INTEL_X86_SPEC);
			if (ret)
				info->is_speculative = PFM_EVENT_INFO_SPEC_TRUE;
			else
				info->is_speculative = PFM_EVENT_INFO_SPEC_FALSE;
		} else
			info->is_speculative = PFM_EVENT_INFO_SPEC_NA;
	} else {
		idx = intel_x86_attr2mod(this, pidx, attr_idx);
		info->name = atdesc[idx].name;
		info->desc = atdesc[idx].desc;
		info->type = atdesc[idx].type;
		info->equiv= NULL;
		info->code = idx;
		info->is_dfl = 0;
		info->is_precise = 0;
		info->is_speculative = PFM_EVENT_INFO_SPEC_NA;
		info->support_hw_smpl = 0;
	}

	info->ctrl = PFM_ATTR_CTRL_PMU;
	info->idx = idx; /* namespace specific index */
	info->dfl_val64 = 0;

	return PFM_SUCCESS;
}

int
pfm_intel_x86_get_event_info(void *this, int idx, pfm_event_info_t *info)
{
	const intel_x86_entry_t *pe = this_pe(this);
	pfmlib_pmu_t *pmu = this;
	int has_extpebs = pmu->flags & INTEL_X86_PMU_FL_EXTPEBS;

	if (!is_model_event(this, idx)) {
		DPRINT("invalid event index %d\n", idx);
		return PFM_ERR_INVAL;
	}

	info->name  = pe[idx].name;
	info->desc  = pe[idx].desc;
	info->code  = pe[idx].code;
	info->equiv = pe[idx].equiv;
	info->idx   = idx; /* private index */
	info->pmu   = pmu->pmu;
	/*
	 * no    umask: event supports PEBS
	 * with umasks: at least one umask supports PEBS
	 */
	info->is_precise = intel_x86_eflag(this, idx, INTEL_X86_PEBS);
	/*
	 * if PEBS is supported, then hw buffer sampling is also supported
	 * because PEBS is a hw buffer
	 *
	 * if the PMU supports ExtendedPEBS, then all events can be
	 * recorded using the PEBS buffer. They will all benefit from
	 * the sampling buffer feature. They will not all become precise.
	 * Only the precise at-retirement events will be skidless. Though
	 * by construction PEBS also limits the skid for all events.
	 */
	info->support_hw_smpl = (info->is_precise || has_extpebs);

	if (pmu->flags & PFMLIB_PMU_FL_SPEC) {
		int ret = intel_x86_eflag(this, idx, INTEL_X86_SPEC);
		if (ret)
			info->is_speculative = PFM_EVENT_INFO_SPEC_TRUE;
		else
			info->is_speculative = PFM_EVENT_INFO_SPEC_FALSE;
	}

	info->nattrs  = intel_x86_num_umasks(this, idx);
	info->nattrs += intel_x86_num_mods(this, idx);

	return PFM_SUCCESS;
}

int
pfm_intel_x86_valid_pebs(pfmlib_event_desc_t *e)
{
	pfmlib_event_attr_info_t *a;
	int i, npebs = 0, numasks = 0;

	/* first check at the event level */
	if (intel_x86_eflag(e->pmu, e->event, INTEL_X86_PEBS))
		return PFM_SUCCESS;

	/*
	 * next check the umasks
	 *
	 * we do not assume we are calling after
	 * pfm_intel_x86_ge_event_encoding(), therefore
	 * we check the unit masks again.
	 * They must all be PEBS-capable.
	 */
	for(i=0; i < e->nattrs; i++) {

		a = attr(e, i);

		if (a->ctrl != PFM_ATTR_CTRL_PMU || a->type != PFM_ATTR_UMASK)
			continue;

		numasks++;
		if (intel_x86_uflag(e->pmu, e->event, a->idx, INTEL_X86_PEBS))
			npebs++;
	}
	return npebs == numasks ? PFM_SUCCESS : PFM_ERR_FEATCOMB;
}

unsigned int
pfm_intel_x86_get_event_nattrs(void *this, int pidx)
{
	unsigned int nattrs;
	nattrs  = intel_x86_num_umasks(this, pidx);
	nattrs += intel_x86_num_mods(this, pidx);
	return nattrs;
}

int
pfm_intel_x86_can_auto_encode(void *this, int pidx, int uidx)
{
	int numasks;

	if (intel_x86_eflag(this, pidx, INTEL_X86_NO_AUTOENCODE))
		return 0;

	numasks = intel_x86_num_umasks(this, pidx);
	if (uidx >= numasks)
		return 0;

	return !intel_x86_uflag(this, pidx, uidx, INTEL_X86_NO_AUTOENCODE);
}

static int
intel_x86_event_valid(void *this, int i)
{
	const intel_x86_entry_t *pe = this_pe(this);
	pfmlib_pmu_t *pmu = this;

        return pe[i].model == 0 || pe[i].model == pmu->pmu;
}

int
pfm_intel_x86_get_num_events(void *this)
{
	pfmlib_pmu_t *pmu = this;
	int i, num = 0;

	/*
	 * count actual number of events for specific PMU.
	 * Table may contain more events for the family than
	 * what a specific model actually supports.
	 */
	for (i = 0; i < pmu->pme_count; i++)
		if (intel_x86_event_valid(this, i))
			num++;
	return num;
}
