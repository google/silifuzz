/*
 * pfmlib_intel_snbep_unc.c : Intel SandyBridge-EP uncore PMU common code
 *
 * Copyright (c) 2012 Google, Inc
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
#include "pfmlib_intel_snbep_unc_priv.h"

const pfmlib_attr_desc_t snbep_unc_mods[]={
	PFM_ATTR_B("e", "edge detect"),			/* edge */
	PFM_ATTR_B("i", "invert"),			/* invert */
	PFM_ATTR_I("t", "threshold in range [0-255]"),	/* threshold */
	PFM_ATTR_I("t", "threshold in range [0-31]"),	/* threshold */
	PFM_ATTR_I("tf", "thread id filter [0-1]"),	/* thread id */
	PFM_ATTR_I("cf", "core id filter, includes non-thread data in bit 4 [0-15]"),	/* core id (ivbep) */
	PFM_ATTR_I("nf", "node id bitmask filter [0-255]"),/* nodeid mask filter0 */
	PFM_ATTR_I("ff", "frequency >= 100Mhz * [0-255]"),/* freq filter */
	PFM_ATTR_I("addr", "physical address matcher [40 bits]"),/* address matcher */
	PFM_ATTR_I("nf", "node id bitmask filter [0-255]"),/* nodeid mask filter1 */
	PFM_ATTR_B("isoc", "match isochronous requests"),   /* isochronous */
	PFM_ATTR_B("nc", "match non-coherent requests"),   /* non-coherent */
	PFM_ATTR_I("cf", "core id filter, includes non-thread data in bit 5 [0-63]"),	/* core id (hswep) */
	PFM_ATTR_I("tf", "thread id filter [0-3]"),	 /* thread id (skx)*/
	PFM_ATTR_I("cf", "source id filter [0-63]"),	 /* src-id/core-id (skx) */
	PFM_ATTR_B("loc", "match on local node target"), /* loc filter1 (skx) */
	PFM_ATTR_B("rem", "match on remote node target"),/* rem filter1 (skx) */
	PFM_ATTR_B("lmem", "local memory cacheable"),	 /* nm filter1 (skx) */
	PFM_ATTR_B("rmem", "remote memory cacheable"),	 /* not_nm filter1 (skx) */
	PFM_ATTR_I("dnid", "destination node id [0-15]"), /* SKX:UPI */
	PFM_ATTR_I("rcsnid", "destination RCS Node id [0-15]"), /* SKX:UPI */
	PFM_ATTR_I("t", "threshold in range [0-63]"),	/* threshold */
	PFM_ATTR_B("occ_i", "occupancy event invert"),	/* invert occupancy event */
	PFM_ATTR_B("occ_e", "occupancy event edge "),	/* edge occupancy event */
	PFM_ATTR_NULL
};

int
pfm_intel_snbep_unc_detect(void *this)
{
	int ret;

	ret = pfm_intel_x86_detect();
	if (ret != PFM_SUCCESS)

	if (pfm_intel_x86_cfg.family != 6)
		return PFM_ERR_NOTSUPP;

	switch(pfm_intel_x86_cfg.model) {
		case 45: /* SandyBridge-EP */
			  break;
		default:
			return PFM_ERR_NOTSUPP;
	}
	return PFM_SUCCESS;
}

int
pfm_intel_ivbep_unc_detect(void *this)
{
       int ret;

       ret = pfm_intel_x86_detect();
       if (ret != PFM_SUCCESS)

       if (pfm_intel_x86_cfg.family != 6)
               return PFM_ERR_NOTSUPP;

       switch(pfm_intel_x86_cfg.model) {
               case 62: /* SandyBridge-EP */
                         break;
               default:
                       return PFM_ERR_NOTSUPP;
       }
       return PFM_SUCCESS;
}

int
pfm_intel_hswep_unc_detect(void *this)
{
       int ret;

       ret = pfm_intel_x86_detect();
       if (ret != PFM_SUCCESS)

       if (pfm_intel_x86_cfg.family != 6)
               return PFM_ERR_NOTSUPP;

       switch(pfm_intel_x86_cfg.model) {
               case 63: /* Haswell-EP */
                         break;
               default:
                       return PFM_ERR_NOTSUPP;
       }
       return PFM_SUCCESS;
}

int
pfm_intel_knl_unc_detect(void *this)
{
       int ret;

       ret = pfm_intel_x86_detect();
       if (ret != PFM_SUCCESS)

       if (pfm_intel_x86_cfg.family != 6)
               return PFM_ERR_NOTSUPP;

       switch(pfm_intel_x86_cfg.model) {
               case 87:  /* Knights Landing */
                         break;
               default:
                       return PFM_ERR_NOTSUPP;
       }
       return PFM_SUCCESS;
}

int
pfm_intel_knm_unc_detect(void *this)
{
       int ret;

       ret = pfm_intel_x86_detect();
       if (ret != PFM_SUCCESS)

       if (pfm_intel_x86_cfg.family != 6)
               return PFM_ERR_NOTSUPP;

       switch(pfm_intel_x86_cfg.model) {
               case 133: /* Knights Mill */
                         break;
               default:
                       return PFM_ERR_NOTSUPP;
       }
       return PFM_SUCCESS;
}

int
pfm_intel_bdx_unc_detect(void *this)
{
       int ret;

       ret = pfm_intel_x86_detect();
       if (ret != PFM_SUCCESS)

       if (pfm_intel_x86_cfg.family != 6)
               return PFM_ERR_NOTSUPP;

       switch(pfm_intel_x86_cfg.model) {
               case 79: /* Broadwell X */
               case 86: /* Broadwell X */
                         break;
               default:
                       return PFM_ERR_NOTSUPP;
       }
       return PFM_SUCCESS;
}

int
pfm_intel_skx_unc_detect(void *this)
{
       int ret;

       ret = pfm_intel_x86_detect();
       if (ret != PFM_SUCCESS)

       if (pfm_intel_x86_cfg.family != 6)
               return PFM_ERR_NOTSUPP;

       switch(pfm_intel_x86_cfg.model) {
               case 85: /* Skylake X */
                         break;
               default:
                       return PFM_ERR_NOTSUPP;
       }
       return PFM_SUCCESS;
}

int
pfm_intel_icx_unc_detect(void *this)
{
       int ret;

       ret = pfm_intel_x86_detect();
       if (ret != PFM_SUCCESS)

       if (pfm_intel_x86_cfg.family != 6)
               return PFM_ERR_NOTSUPP;

       switch(pfm_intel_x86_cfg.model) {
               case 106: /* Icelake X */
                         break;
               default:
                       return PFM_ERR_NOTSUPP;
       }
       return PFM_SUCCESS;
}

int
pfm_intel_spr_unc_detect(void *this)
{
       int ret;

       ret = pfm_intel_x86_detect();
       if (ret != PFM_SUCCESS)

       if (pfm_intel_x86_cfg.family != 6)
               return PFM_ERR_NOTSUPP;

       switch(pfm_intel_x86_cfg.model) {
               case 143: /* SapphireRapids */
                         break;
               case 207: /* EmeraldRapids */
                         break;
               default:
                       return PFM_ERR_NOTSUPP;
       }
       return PFM_SUCCESS;
}




static void
display_com(void *this, pfmlib_event_desc_t *e, void *val)
{
	const intel_x86_entry_t *pe = this_pe(this);
	pfm_snbep_unc_reg_t *reg = val;

	__pfm_vbprintf("[UNC=0x%"PRIx64" event=0x%x umask=0x%x en=%d "
		       "inv=%d edge=%d thres=%d] %s\n",
			reg->val,
			reg->com.unc_event,
			reg->com.unc_umask,
			reg->com.unc_en,
			reg->com.unc_inv,
			reg->com.unc_edge,
			reg->com.unc_thres,
			pe[e->event].name);
}

static void
display_reg(void *this, pfmlib_event_desc_t *e, pfm_snbep_unc_reg_t reg)
{
	pfmlib_pmu_t *pmu = this;
	if (pmu->display_reg)
		pmu->display_reg(this, e, &reg);
	else
		display_com(this, e, &reg);
}

static inline int
is_occ_event(void *this, int idx)
{
	pfmlib_pmu_t *pmu = this;
	const intel_x86_entry_t *pe = this_pe(this);

	return (pmu->flags & INTEL_PMU_FL_UNC_OCC) && (pe[idx].code & 0x80);
}

static inline int
get_pcu_filt_band(void *this, pfm_snbep_unc_reg_t reg)
{
#define PCU_FREQ_BAND0_CODE	0xb /* event code for UNC_P_FREQ_BAND0_CYCLES */
	return reg.pcu.unc_event - PCU_FREQ_BAND0_CODE;
}

static inline void
set_filters(void *this, pfm_snbep_unc_reg_t *filters, int event, int umask)
{
	const intel_x86_entry_t *pe = this_pe(this);

	filters[0].val |= pe[event].umasks[umask].ufilters[0] & ((1ULL << 32)-1);
	filters[0].val &= ~(pe[event].umasks[umask].ufilters[0] >> 32);

	filters[1].val |= pe[event].umasks[umask].ufilters[1] & ((1ULL << 32)-1);
	filters[1].val &= ~(pe[event].umasks[umask].ufilters[1] >>32);
}

int
snbep_unc_add_defaults(void *this, pfmlib_event_desc_t *e,
			   unsigned int msk,
			   uint64_t *umask,
			   pfm_snbep_unc_reg_t *filters,
			   unsigned short max_grpid,
			   int *numasks)
{
	const intel_x86_entry_t *pe = this_pe(this);
	const intel_x86_entry_t *ent;
	unsigned int i;
	int j, k, added, skip;
	int idx;

	k = e->nattrs;
	ent = pe+e->event;

	for(i=0; msk; msk >>=1, i++) {

		if (!(msk & 0x1))
			continue;

		added = skip = 0;

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

				set_filters(this, filters, e->event, idx);

				e->attrs[k].id = j; /* pattrs index */
				e->attrs[k].ival = 0;
				k++;

				(*numasks)++;
				added++;
				if (intel_x86_eflag(this, e->event, INTEL_X86_GRP_EXCL))
					goto done;

				if (intel_x86_uflag(this, e->event, idx, INTEL_X86_EXCL_GRP_GT)) {
					if (max_grpid != INTEL_X86_MAX_GRPID) {
						DPRINT("two max_grpid, old=%d new=%d\n", max_grpid, get_grpid(ent->umasks[idx].grpid));
						return PFM_ERR_UMASK;
					}
					max_grpid = get_grpid(ent->umasks[idx].grpid);
				}
			}
		}
		if (!added && !skip) {
			DPRINT("no default found for event %s unit mask group %d (max_grpid=%d, i=%d)\n", ent->name, i, max_grpid, i);
			return PFM_ERR_UMASK;
		}
	}
	DPRINT("max_grpid=%d nattrs=%d k=%d umask=0x%"PRIx64"\n", max_grpid, e->nattrs, k, *umask);
done:
	e->nattrs = k;
	return PFM_SUCCESS;
}


/*
 * common encoding routine
 */
int
pfm_intel_snbep_unc_get_encoding(void *this, pfmlib_event_desc_t *e)
{
	const intel_x86_entry_t *pe = this_pe(this);
	unsigned int grpmsk, ugrpmsk = 0;
	unsigned short max_grpid = INTEL_X86_MAX_GRPID;
	unsigned short last_grpid =  INTEL_X86_MAX_GRPID;
	unsigned short req_grpid;
	int umodmsk = 0, modmsk_r = 0;
	int pcu_filt_band = -1;
	pfm_snbep_unc_reg_t reg;
	pfm_snbep_unc_reg_t filters[INTEL_X86_MAX_FILTERS];
	pfm_snbep_unc_reg_t addr;
	pfmlib_event_attr_info_t *a;
	uint64_t val, umask1, umask2;
	int k, ret, numasks = 0;
	int must_have_filt0 = 0;
	int max_req_grpid = -1;
	unsigned short grpid;
	int grpcounts[INTEL_X86_NUM_GRP];
	int req_grps[INTEL_X86_NUM_GRP];
	int ncombo[INTEL_X86_NUM_GRP];
	char umask_str[PFMLIB_EVT_MAX_NAME_LEN];

	memset(grpcounts, 0, sizeof(grpcounts));
	memset(ncombo, 0, sizeof(ncombo));
	memset(filters, 0, sizeof(filters));

	addr.val = 0;

	umask_str[0] = e->fstr[0] = '\0';

	reg.val = val = pe[e->event].code;

	/* take into account hardcoded umask */
	umask1 = (val >> 8);
	umask2 = umask1;

	grpmsk = (1 << pe[e->event].ngrp)-1;

	modmsk_r = pe[e->event].modmsk_req;

	if (intel_x86_eflag(this, e->event, INTEL_X86_FORCE_FILT0))
		must_have_filt0 = 1;

	for(k=0; k < e->nattrs; k++) {
		a = attr(e, k);

		if (a->ctrl != PFM_ATTR_CTRL_PMU)
			continue;

		if (a->type == PFM_ATTR_UMASK) {
			uint64_t um;

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

			/*
			 * if more than one umask in this group but one is marked
			 * with ncombo, then fail. It is okay to combine umask within
			 * a group as long as none is tagged with NCOMBO
			 */
			if (grpcounts[grpid] > 1 && ncombo[grpid])  {
				DPRINT("umask %s does not support unit mask combination within group %d\n", pe[e->event].umasks[a->idx].uname, grpid);
				return PFM_ERR_FEATCOMB;
			}

			last_grpid = grpid;

			um = pe[e->event].umasks[a->idx].ucode;

			set_filters(this, filters, e->event, a->idx);

			um >>= 8;
			umask2  |= um;

			ugrpmsk |= 1 << grpid;

			/* PCU occ event */
			if (is_occ_event(this, e->event)) {
				reg.pcu.unc_occ = umask2 >> 6;
				umask2 = 0;
			} else
				reg.val |= umask2 << 8;

			evt_strcat(umask_str, ":%s", pe[e->event].umasks[a->idx].uname);

			modmsk_r |= pe[e->event].umasks[a->idx].umodmsk_req;
			numasks++;

		} else if (a->type == PFM_ATTR_RAW_UMASK) {

			/* there can only be one RAW_UMASK per event */

			/* sanity check */
			if (a->idx & ~0xff) {
				DPRINT("raw umask is 8-bit wide\n");
				return PFM_ERR_ATTR;
			}
			/* override umask */
			umask2 = a->idx & 0xff;
			ugrpmsk = grpmsk;
			numasks++;
		} else {
			uint64_t ival = e->attrs[k].ival;
			switch(a->idx) {
				case SNBEP_UNC_ATTR_I: /* invert */
					if (is_occ_event(this, e->event))
						reg.pcu.unc_occ_inv = !!ival;
					else
						reg.com.unc_inv = !!ival;
					umodmsk |= _SNBEP_UNC_ATTR_I;
					break;
				case SNBEP_UNC_ATTR_E: /* edge */
					if (is_occ_event(this, e->event))
						reg.pcu.unc_occ_edge = !!ival;
					else
						reg.com.unc_edge = !!ival;
					umodmsk |= _SNBEP_UNC_ATTR_E;
					break;
				case SNBEP_UNC_ATTR_T8: /* counter-mask */
					/* already forced, cannot overwrite */
					if (ival > 255)
						return PFM_ERR_ATTR_VAL;
					reg.com.unc_thres = ival;
					umodmsk |= _SNBEP_UNC_ATTR_T8;
					break;
				case SNBEP_UNC_ATTR_T5: /* pcu counter-mask */
					/* already forced, cannot overwrite */
					if (ival > 31)
						return PFM_ERR_ATTR_VAL;
					reg.pcu.unc_thres = ival;
					umodmsk |= _SNBEP_UNC_ATTR_T5;
					break;
				case SNBEP_UNC_ATTR_T6: /* counter-mask */
					/* already forced, cannot overwrite */
					if (ival > 63)
						return PFM_ERR_ATTR_VAL;
					reg.com.unc_thres = ival;
					umodmsk |= _SNBEP_UNC_ATTR_T6;
					break;
				case SNBEP_UNC_ATTR_TF: /* thread id */
					if (ival > 1) {
						DPRINT("invalid thread id, must be < 1");
						return PFM_ERR_ATTR_VAL;
					}
					reg.cbo.unc_tid = 1;
					must_have_filt0 = 1;
					filters[0].cbo_filt.tid = ival;
					umodmsk |= _SNBEP_UNC_ATTR_TF;
					break;
				case SNBEP_UNC_ATTR_TF1: /* thread id skx */
					if (ival > 7)
						return PFM_ERR_ATTR_VAL;
					reg.cha.unc_tid = 1;
					filters[0].skx_cha_filt0.tid = ival; /* includes non-thread data */
					must_have_filt0 = 1;
					umodmsk |= _SNBEP_UNC_ATTR_TF1;
					break;
				case SNBEP_UNC_ATTR_CF: /* core id */
					if (ival > 15)
						return PFM_ERR_ATTR_VAL;
					reg.cbo.unc_tid = 1;
					filters[0].cbo_filt.cid = ival;
					must_have_filt0 = 1;
					umodmsk |= _SNBEP_UNC_ATTR_CF;
					break;
				case SNBEP_UNC_ATTR_CF1: /* core id */
					if (ival > 63)
						return PFM_ERR_ATTR_VAL;
					reg.cbo.unc_tid = 1;
					filters[0].hswep_cbo_filt0.cid = ival; /* includes non-thread data */
					must_have_filt0 = 1;
					umodmsk |= _SNBEP_UNC_ATTR_CF1;
					break;
				case SNBEP_UNC_ATTR_NF: /* node id filter0 */
					if (ival > 255 || ival == 0) {
						DPRINT("invalid nf,  0 < nf < 256\n");
						return PFM_ERR_ATTR_VAL;
					}
					filters[0].cbo_filt.nid = ival;
					umodmsk |= _SNBEP_UNC_ATTR_NF;
					break;
				case SNBEP_UNC_ATTR_NF1: /* node id filter1 */
					if (ival > 255 || ival == 0) {
						DPRINT("invalid nf,  0 < nf < 256\n");
						return PFM_ERR_ATTR_VAL;
					}
					filters[1].ivbep_cbo_filt1.nid = ival;
					umodmsk |= _SNBEP_UNC_ATTR_NF1;
					break;
				case SNBEP_UNC_ATTR_CF2: /* src-id/core-id skx */
					if (ival > 64)
						return PFM_ERR_ATTR_VAL;
					reg.cha.unc_tid = 1;
					filters[0].skx_cha_filt0.sid = ival;
					must_have_filt0 = 1;
					umodmsk |= _SNBEP_UNC_ATTR_CF2;
					break;
				case SNBEP_UNC_ATTR_FF: /* freq band filter */
					if (ival > 255)
						return PFM_ERR_ATTR_VAL;
					pcu_filt_band = get_pcu_filt_band(this, reg);
					filters[0].val = ival << (pcu_filt_band * 8);
					umodmsk |= _SNBEP_UNC_ATTR_FF;
					break;
				case SNBEP_UNC_ATTR_A: /* addr filter */
					if (ival & ~((1ULL << 40)-1)) {
						DPRINT("address filter 40bits max\n");
						return PFM_ERR_ATTR_VAL;
					}
					addr.ha_addr.lo_addr = ival; /* LSB 26 bits */
					addr.ha_addr.hi_addr = (ival >> 26) & ((1ULL << 14)-1);
					umodmsk |= _SNBEP_UNC_ATTR_A;
					break;
				case SNBEP_UNC_ATTR_ISOC: /* isoc filter */
					filters[1].ivbep_cbo_filt1.isoc = !!ival;
					break;
				case SNBEP_UNC_ATTR_NC: /* nc filter */
					filters[1].ivbep_cbo_filt1.nc = !!ival;
					break;
				case SNBEP_UNC_ATTR_LOC: /* local target skx */
					filters[1].skx_cha_filt1.loc = !!ival;
					break;
				case SNBEP_UNC_ATTR_REM: /* remote target skx */
					filters[1].skx_cha_filt1.rem = !!ival;
					break;
				case SNBEP_UNC_ATTR_LMEM: /* local target skx */
					filters[1].skx_cha_filt1.loc = !!ival;
					break;
				case SNBEP_UNC_ATTR_RMEM: /* local memory skx */
					filters[1].skx_cha_filt1.not_nm = !!ival;
					break;
				case SNBEP_UNC_ATTR_DNID: /* destination node id skx */
					if (ival > 15) {
						DPRINT("dnid must be [0-15]\n");
						return PFM_ERR_ATTR_VAL;
					}
					filters[0].skx_upi_filt.dnid = ival;
					filters[0].skx_upi_filt.en_dnidd = 1;
					break;
				case SNBEP_UNC_ATTR_RCSNID: /* RCS node id skx */
					if (ival > 15) {
						DPRINT("rcsnid must be [0-15]\n");
						return PFM_ERR_ATTR_VAL;
					}
					filters[0].skx_upi_filt.rcsnid = ival;
					filters[0].skx_upi_filt.en_rcsnid = 1;
					break;
				case SNBEP_UNC_ATTR_OCC_I: /* occ_i */
					reg.icx_pcu.unc_occ_inv = !!ival;
					umodmsk |= _SNBEP_UNC_ATTR_OCC_I;
					break;
				case SNBEP_UNC_ATTR_OCC_E: /* occ_e */
					reg.icx_pcu.unc_occ_edge = !!ival;
					umodmsk |= _SNBEP_UNC_ATTR_OCC_E;
					break;
				default:
					DPRINT("event %s invalid attribute %d\n", pe[e->event].name, a->idx);
					return PFM_ERR_ATTR;
					
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
	 * check that there is at least of unit mask in each unit mask group
	 */
	if (pe[e->event].numasks && (ugrpmsk != grpmsk || ugrpmsk == 0)) {
		uint64_t um = 0;
		ugrpmsk ^= grpmsk;
		ret = snbep_unc_add_defaults(this, e, ugrpmsk, &um, filters, max_grpid, &numasks);
		if (ret != PFM_SUCCESS)
			return ret;
		umask2 |= um;
	}
	/* if event has umasks, then likely at least one must be set */
	if (pe[e->event].numasks && numasks == 0) {
		DPRINT("event has umasks but none specified\n");
		return PFM_ERR_ATTR;
	}

	/*
	 * nf= is only required on some events in CBO
	 */
	if (!(modmsk_r & _SNBEP_UNC_ATTR_NF) && (umodmsk & _SNBEP_UNC_ATTR_NF)) {
		DPRINT("using nf= on an umask which does not require it\n");
		return PFM_ERR_ATTR;
	}
	if (!(modmsk_r & _SNBEP_UNC_ATTR_NF1) && (umodmsk & _SNBEP_UNC_ATTR_NF1)) {
		DPRINT("using nf= on an umask which does not require it\n");
		return PFM_ERR_ATTR;
	}

	if (modmsk_r && !(umodmsk & modmsk_r)) {
		DPRINT("required modifiers missing: 0x%x\n", modmsk_r);
		return PFM_ERR_ATTR;
	}

	/*
	 * fixup filt1.all_opc based on values of the filter
	 */
	if (is_cha_filt_event(this, 1, reg)) {
		if (filters[1].val == 0)
			/* default value: rem=loc=nm=not_nm=all_opc=1 */
			filters[1].val =0x3b;
		else if (filters[1].skx_cha_filt1.opc0 || filters[1].skx_cha_filt1.opc1) {
			/* enable opcode filtering */
			filters[1].val &= ~(1ULL << 3);
		}
	}

	evt_strcat(e->fstr, "%s", pe[e->event].name);
	pfmlib_sort_attr(e);

	for(k = 0; k < e->nattrs; k++) {
		a = attr(e, k);
		if (a->ctrl != PFM_ATTR_CTRL_PMU)
			continue;
		if (a->type == PFM_ATTR_UMASK)
			evt_strcat(e->fstr, ":%s", pe[e->event].umasks[a->idx].uname);
		else if (a->type == PFM_ATTR_RAW_UMASK)
			evt_strcat(e->fstr, ":0x%x", a->idx);
	}
	DPRINT("umask2=0x%"PRIx64" umask1=0x%"PRIx64"\n", umask2, umask1);
	e->count = 0;
	reg.val |= (umask1 | umask2)  << 8;

	e->codes[e->count++] = reg.val;

	/*
	 * handles filters
	 */
	if (filters[0].val || filters[1].val || must_have_filt0)
		e->codes[e->count++] = filters[0].val;
	if (filters[1].val)
		e->codes[e->count++] = filters[1].val;

	/* HA address matcher */
	if (addr.val)
		e->codes[e->count++] = addr.val;

	for (k = 0; k < e->npattrs; k++) {
		int idx;

		if (e->pattrs[k].ctrl != PFM_ATTR_CTRL_PMU)
			continue;

		if (e->pattrs[k].type == PFM_ATTR_UMASK)
			continue;

		idx = e->pattrs[k].idx;
		switch(idx) {
		case SNBEP_UNC_ATTR_E:
			if (is_occ_event(this, e->event))
				evt_strcat(e->fstr, ":%s=%lu", snbep_unc_mods[idx].name, reg.pcu.unc_occ_edge);
			else
				evt_strcat(e->fstr, ":%s=%lu", snbep_unc_mods[idx].name, reg.com.unc_edge);
			break;
		case SNBEP_UNC_ATTR_I:
			if (is_occ_event(this, e->event))
				evt_strcat(e->fstr, ":%s=%lu", snbep_unc_mods[idx].name, reg.pcu.unc_occ_inv);
			else
				evt_strcat(e->fstr, ":%s=%lu", snbep_unc_mods[idx].name, reg.com.unc_inv);
			break;
		case SNBEP_UNC_ATTR_T8:
			evt_strcat(e->fstr, ":%s=%lu", snbep_unc_mods[idx].name, reg.com.unc_thres);
			break;
		case SNBEP_UNC_ATTR_T5:
			evt_strcat(e->fstr, ":%s=%lu", snbep_unc_mods[idx].name, reg.pcu.unc_thres);
			break;
		case SNBEP_UNC_ATTR_TF:
			evt_strcat(e->fstr, ":%s=%lu", snbep_unc_mods[idx].name, reg.cbo.unc_tid);
			break;
		case SNBEP_UNC_ATTR_TF1:
			evt_strcat(e->fstr, ":%s=%lu", snbep_unc_mods[idx].name, filters[0].skx_cha_filt0.tid);
			break;
		case SNBEP_UNC_ATTR_CF:
			evt_strcat(e->fstr, ":%s=%lu", snbep_unc_mods[idx].name, filters[0].cbo_filt.cid);
			break;
		case SNBEP_UNC_ATTR_CF1:
			evt_strcat(e->fstr, ":%s=%lu", snbep_unc_mods[idx].name, filters[0].hswep_cbo_filt0.cid);
			break;
		case SNBEP_UNC_ATTR_CF2:
			evt_strcat(e->fstr, ":%s=%lu", snbep_unc_mods[idx].name, filters[0].skx_cha_filt0.sid);
			break;
		case SNBEP_UNC_ATTR_FF:
			evt_strcat(e->fstr, ":%s=%lu", snbep_unc_mods[idx].name, (filters[0].val >> (pcu_filt_band*8)) & 0xff);
			break;
		case SNBEP_UNC_ATTR_ISOC:
			evt_strcat(e->fstr, ":%s=%lu", snbep_unc_mods[idx].name, filters[1].ivbep_cbo_filt1.isoc);
			break;
		case SNBEP_UNC_ATTR_NC:
			evt_strcat(e->fstr, ":%s=%lu", snbep_unc_mods[idx].name, filters[1].ivbep_cbo_filt1.nc);
			break;
		case SNBEP_UNC_ATTR_NF:
			if (modmsk_r & _SNBEP_UNC_ATTR_NF)
				evt_strcat(e->fstr, ":%s=%lu", snbep_unc_mods[idx].name, filters[0].cbo_filt.nid);
			break;
		case SNBEP_UNC_ATTR_NF1:
			if (modmsk_r & _SNBEP_UNC_ATTR_NF1)
				evt_strcat(e->fstr, ":%s=%lu", snbep_unc_mods[idx].name, filters[1].ivbep_cbo_filt1.nid);
			break;
		case SNBEP_UNC_ATTR_A:
			evt_strcat(e->fstr, ":%s=0x%lx", snbep_unc_mods[idx].name,
				   addr.ha_addr.hi_addr << 26 | addr.ha_addr.lo_addr);
			break;
		case SNBEP_UNC_ATTR_REM:
			evt_strcat(e->fstr, ":%s=%lu", snbep_unc_mods[idx].name, filters[1].skx_cha_filt1.rem);
			break;
		case SNBEP_UNC_ATTR_LOC:
			evt_strcat(e->fstr, ":%s=%lu", snbep_unc_mods[idx].name, filters[1].skx_cha_filt1.loc);
			break;
		case SNBEP_UNC_ATTR_RMEM:
			evt_strcat(e->fstr, ":%s=%lu", snbep_unc_mods[idx].name, filters[1].skx_cha_filt1.rem);
			break;
		case SNBEP_UNC_ATTR_LMEM:
			evt_strcat(e->fstr, ":%s=%lu", snbep_unc_mods[idx].name, filters[1].skx_cha_filt1.loc);
			break;
		case SNBEP_UNC_ATTR_DNID:
			evt_strcat(e->fstr, ":%s=%lu", snbep_unc_mods[idx].name, filters[0].skx_upi_filt.dnid);
			break;
		case SNBEP_UNC_ATTR_RCSNID:
			evt_strcat(e->fstr, ":%s=%lu", snbep_unc_mods[idx].name, filters[0].skx_upi_filt.rcsnid);
			break;
		case SNBEP_UNC_ATTR_T6:
			evt_strcat(e->fstr, ":%s=%lu", snbep_unc_mods[idx].name, reg.icx_pcu.unc_thres);
			break;
		case SNBEP_UNC_ATTR_OCC_I:
			evt_strcat(e->fstr, ":%s=%lu", snbep_unc_mods[idx].name, reg.icx_pcu.unc_occ_inv);
			break;
		case SNBEP_UNC_ATTR_OCC_E:
			evt_strcat(e->fstr, ":%s=%lu", snbep_unc_mods[idx].name, reg.icx_pcu.unc_occ_edge);
			break;
		default:
			DPRINT("unknown attribute %d for event %s\n", idx, pe[e->event].name);
			return PFM_ERR_ATTR;
		}
	}
	display_reg(this, e, reg);
	return PFM_SUCCESS;
}

int
pfm_intel_snbep_unc_can_auto_encode(void *this, int pidx, int uidx)
{
	if (intel_x86_eflag(this, pidx, INTEL_X86_NO_AUTOENCODE))
		return 0;

	return !intel_x86_uflag(this, pidx, uidx, INTEL_X86_NO_AUTOENCODE);
}

int
pfm_intel_snbep_unc_get_event_attr_info(void *this, int pidx, int attr_idx, pfmlib_event_attr_info_t *info)
{
	const intel_x86_entry_t *pe = this_pe(this);
	const pfmlib_attr_desc_t *atdesc = this_atdesc(this);
	int numasks, idx;

	numasks = intel_x86_num_umasks(this, pidx);
	if (attr_idx < numasks) {
		idx = intel_x86_attr2umask(this, pidx, attr_idx);
		info->name = pe[pidx].umasks[idx].uname;
		info->desc = pe[pidx].umasks[idx].udesc;
		info->equiv= pe[pidx].umasks[idx].uequiv;

		info->code = pe[pidx].umasks[idx].ucode;

		if (!intel_x86_uflag(this, pidx, idx, INTEL_X86_CODE_OVERRIDE))
			info->code >>= 8;

		if (info->code == 0)
			info->code = pe[pidx].umasks[idx].ufilters[0];

		info->type = PFM_ATTR_UMASK;
		info->is_dfl = intel_x86_uflag(this, pidx, idx, INTEL_X86_DFL);
		info->is_precise = intel_x86_uflag(this, pidx, idx, INTEL_X86_PEBS);
	} else {
		idx = intel_x86_attr2mod(this, pidx, attr_idx);
		info->name = atdesc[idx].name;
		info->desc = atdesc[idx].desc;
		info->type = atdesc[idx].type;
		info->equiv= NULL;
		info->code = idx;
		info->is_dfl = 0;
		info->is_precise = 0;
	}

	info->ctrl = PFM_ATTR_CTRL_PMU;
	info->idx = idx; /* namespace specific index */
	info->dfl_val64 = 0;
	info->support_hw_smpl = 0;

	return PFM_SUCCESS;
}
