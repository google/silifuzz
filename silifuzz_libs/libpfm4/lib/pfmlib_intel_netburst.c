/*
 * Copyright (c) 2005-2006 Hewlett-Packard Development Company, L.P.
 * Copyright (c) 2006 IBM Corp.
 * Contributed by Kevin Corry <kevcorry@us.ibm.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * pfmlib_intel_netburst.c
 *
 * Support for the Pentium4/Xeon/EM64T processor family (family=15).
 */
/* private headers */
#include "pfmlib_priv.h"
#include "pfmlib_intel_netburst_priv.h"
#include "pfmlib_intel_x86_priv.h"
#include "events/intel_netburst_events.h"

const pfmlib_attr_desc_t netburst_mods[]={
	PFM_ATTR_B("u", "monitor at priv level 1, 2, 3"),	/* monitor priv level 1, 2, 3 */
	PFM_ATTR_B("k", "monitor at priv level 0"),		/* monitor priv level 0 */
	PFM_ATTR_B("cmpl", "complement"),			/* set: <=, clear: > */
	PFM_ATTR_B("e", "edge"),				/* edge */
	PFM_ATTR_I("thr", "event threshold in range [0-15]"),	/* threshold */
};
#define NETBURST_MODS_COUNT (sizeof(netburst_mods)/sizeof(pfmlib_attr_desc_t))


extern pfmlib_pmu_t netburst_support;

static inline int
netburst_get_numasks(int pidx)
{
	int i = 0;
	/*
	 * name = NULL is end-marker
	 */
	while (netburst_events[pidx].event_masks[i].name)
		i++;
	return i;
}

static void
netburst_display_reg(pfmlib_event_desc_t *e)
{
	netburst_escr_value_t escr;
	netburst_cccr_value_t cccr;

	escr.val = e->codes[0];
	cccr.val = e->codes[1];

	__pfm_vbprintf("[0x%"PRIx64" 0x%"PRIx64" 0x%"PRIx64" usr=%d os=%d tag_ena=%d tag_val=%d "
		       "evmask=0x%x evsel=0x%x escr_sel=0x%x comp=%d cmpl=%d thr=%d e=%d",
			escr,
			cccr,
			e->codes[2], /* perf_event code */
			escr.bits.t0_usr, /* t1 is identical */
			escr.bits.t0_os,  /* t1 is identical */
			escr.bits.tag_enable,
			escr.bits.tag_value,
			escr.bits.event_mask,
			escr.bits.event_select,
			cccr.bits.escr_select,
			cccr.bits.compare,
			cccr.bits.complement,
			cccr.bits.threshold,
			cccr.bits.edge);

	__pfm_vbprintf("] %s\n", e->fstr);
}

static int
netburst_add_defaults(pfmlib_event_desc_t *e, unsigned int *evmask)
{
	int i, n;

	n = netburst_get_numasks(e->event);

	for (i = 0; i < n; i++) {

		if (netburst_events[e->event].event_masks[i].flags & NETBURST_FL_DFL)
			goto found;
	}
	return PFM_ERR_ATTR;
found:
	*evmask = 1 << netburst_events[e->event].event_masks[i].bit;
	n = e->nattrs;
	e->attrs[n].id = i;
	e->attrs[n].ival = i;
	e->nattrs = n+1;

	return PFM_SUCCESS;
}

int
pfm_netburst_get_encoding(void *this, pfmlib_event_desc_t *e)
{
	pfmlib_event_attr_info_t *a;
	netburst_escr_value_t escr;
	netburst_cccr_value_t cccr;
	unsigned int evmask = 0;
	unsigned int plmmsk = 0;
	int umask_done = 0;
	const char *n;
	int k, id, bit, ret;
	int tag_enable = 0, tag_value = 0;

	e->fstr[0] = '\0';

	escr.val = 0;
	cccr.val = 0;

	for(k=0; k < e->nattrs; k++) {
		a = attr(e, k);

		if (a->ctrl != PFM_ATTR_CTRL_PMU)
			continue;

		if (a->type == PFM_ATTR_UMASK) {

			bit = netburst_events[e->event].event_masks[a->idx].bit;
			n   = netburst_events[e->event].event_masks[a->idx].name;
			/*
			 * umask combination seems possible, although it does
			 * not always make sense, e.g., BOGUS vs. NBOGUS
			 */
			if (bit < EVENT_MASK_BITS && n) {
				evmask |= (1 << bit);
			} else	if (bit >= EVENT_MASK_BITS && n) {
				tag_value |= (1 << (bit - EVENT_MASK_BITS));
				tag_enable = 1;
			}
			umask_done = 1;
		} else if (a->type == PFM_ATTR_RAW_UMASK) {
			/* should not happen */
			return PFM_ERR_ATTR;
		} else {
			uint64_t ival = e->attrs[k].ival;
			switch (a->idx) {
			case NETBURST_ATTR_U:
				escr.bits.t1_usr = !!ival;
				escr.bits.t0_usr = !!ival;
				plmmsk |= _NETBURST_ATTR_U;
				break;
			case NETBURST_ATTR_K:
				escr.bits.t1_os = !!ival;
				escr.bits.t0_os = !!ival;
				plmmsk |= _NETBURST_ATTR_K;
				break;
			case NETBURST_ATTR_E:
				if (ival) {
					cccr.bits.compare = 1;
					cccr.bits.edge = 1;
				}
				break;
			case NETBURST_ATTR_C:
				if (ival) {
					cccr.bits.compare = 1;
					cccr.bits.complement = 1;
				}
				break;
			case NETBURST_ATTR_T:
				if (ival > 15)
					return PFM_ERR_ATTR_VAL;

				if (ival) {
					cccr.bits.compare = 1;
					cccr.bits.threshold = ival;
				}
				break;
			default:
				return PFM_ERR_ATTR;
			}
		}
	}
	/*
	 * handle case where no priv level mask was passed.
	 * then we use the dfl_plm
	 */
	if (!(plmmsk & (_NETBURST_ATTR_K|_NETBURST_ATTR_U))) {
		if (e->dfl_plm & PFM_PLM0) {
			escr.bits.t1_os = 1;
			escr.bits.t0_os = 1;
		}
		if (e->dfl_plm & PFM_PLM3) {
			escr.bits.t1_usr = 1;
			escr.bits.t0_usr = 1;
		}
	}

	if (!umask_done) {
		ret = netburst_add_defaults(e, &evmask);
		if (ret != PFM_SUCCESS)
			return ret;
	}

	escr.bits.tag_enable   = tag_enable;
	escr.bits.tag_value    = tag_value;
	escr.bits.event_mask   = evmask;
	escr.bits.event_select = netburst_events[e->event].event_select;


	cccr.bits.enable        = 1;
	cccr.bits.escr_select   = netburst_events[e->event].escr_select;
	cccr.bits.active_thread = 3;

	if (e->event == PME_REPLAY_EVENT)
		escr.bits.event_mask &= P4_REPLAY_REAL_MASK;	 /* remove virtual mask bits */

	/*
	 * reorder all the attributes such that the fstr appears always
	 * the same regardless of how the attributes were submitted.
	 */
	evt_strcat(e->fstr, "%s", netburst_events[e->event].name);
	pfmlib_sort_attr(e);
	for(k=0; k < e->nattrs; k++) {
		a = attr(e, k);
		if (a->ctrl != PFM_ATTR_CTRL_PMU)
			continue;
		if (a->type == PFM_ATTR_UMASK) {
			id = e->attrs[k].id;
			evt_strcat(e->fstr, ":%s", netburst_events[e->event].event_masks[id].name);
		}
	}

	evt_strcat(e->fstr, ":%s=%lu", netburst_mods[NETBURST_ATTR_K].name, escr.bits.t0_os);
	evt_strcat(e->fstr, ":%s=%lu", netburst_mods[NETBURST_ATTR_U].name, escr.bits.t0_usr);
	evt_strcat(e->fstr, ":%s=%lu", netburst_mods[NETBURST_ATTR_E].name, cccr.bits.edge);
	evt_strcat(e->fstr, ":%s=%lu", netburst_mods[NETBURST_ATTR_C].name, cccr.bits.complement);
	evt_strcat(e->fstr, ":%s=%lu", netburst_mods[NETBURST_ATTR_T].name, cccr.bits.threshold);

	e->count = 2;
	e->codes[0] = escr.val;
	e->codes[1] = cccr.val;

	netburst_display_reg(e);

	return PFM_SUCCESS;
}

static int
pfm_netburst_detect(void *this)
{
	int ret;
	int model;

	ret = pfm_intel_x86_detect();
	if (ret != PFM_SUCCESS)
		return ret;

	if (pfm_intel_x86_cfg.family != 15)
		return PFM_ERR_NOTSUPP;

	model = pfm_intel_x86_cfg.model;
	if (model == 3 || model == 4 || model == 6)
		return PFM_ERR_NOTSUPP;

	return PFM_SUCCESS;
}

static int
pfm_netburst_detect_prescott(void *this)
{
	int ret;
	int model;

	ret = pfm_intel_x86_detect();
	if (ret != PFM_SUCCESS)
		return ret;

	if (pfm_intel_x86_cfg.family != 15)
		return PFM_ERR_NOTSUPP;

	/*
	 * prescott has one more event (instr_completed)
	 */
	model = pfm_intel_x86_cfg.model;
	if (model != 3 && model != 4 && model != 6)
		return PFM_ERR_NOTSUPP;

	return PFM_SUCCESS;
}

static int
pfm_netburst_get_event_first(void *this)
{
	pfmlib_pmu_t *p = this;
	return p->pme_count ? 0 : -1;
}

static int
pfm_netburst_get_event_next(void *this, int idx)
{
	pfmlib_pmu_t *p = this;

	if (idx >= (p->pme_count-1))
		return -1;

	return idx+1;
}

static int
pfm_netburst_event_is_valid(void *this, int pidx)
{
	pfmlib_pmu_t *p = this;
	return pidx >= 0 && pidx < p->pme_count;
}

static int
pfm_netburst_get_event_attr_info(void *this, int pidx, int attr_idx, pfmlib_event_attr_info_t *info)
{
	const netburst_entry_t *pe = this_pe(this);
	int numasks, idx;

	numasks = netburst_get_numasks(pidx);
	if (attr_idx < numasks) {
		//idx = pfm_intel_x86_attr2umask(this, pidx, attr_idx);
		idx = attr_idx;
		info->name = pe[pidx].event_masks[idx].name;
		info->desc = pe[pidx].event_masks[idx].desc;
		info->equiv= NULL;
		info->code = pe[pidx].event_masks[idx].bit;
		info->type = PFM_ATTR_UMASK;
		info->is_dfl = !!(pe[pidx].event_masks[idx].flags & NETBURST_FL_DFL);
	} else {
		idx = attr_idx - numasks;
		info->name = netburst_mods[idx].name;
		info->desc = netburst_mods[idx].desc;
		info->equiv= NULL;
		info->code = idx;
		info->type = netburst_mods[idx].type;
		info->is_dfl = 0;
	}
	info->ctrl = PFM_ATTR_CTRL_PMU;
	info->idx = idx; /* namespace specific index */
	info->dfl_val64 = 0;
	info->is_precise = 0;
	info->support_hw_smpl = 0;

	return PFM_SUCCESS;
}

static int
pfm_netburst_get_event_info(void *this, int idx, pfm_event_info_t *info)
{
	const netburst_entry_t *pe = this_pe(this);
	pfmlib_pmu_t *pmu = this;

	/*
	 * pmu and idx filled out by caller
	 */
	info->name  = pe[idx].name;
	info->desc  = pe[idx].desc;
	info->code  = pe[idx].event_select | (pe[idx].escr_select << 8);
	info->equiv = NULL;
	info->idx   = idx; /* private index */
	info->pmu   = pmu->pmu;

	info->is_precise = 0;
	info->support_hw_smpl = 0;

	info->nattrs  = netburst_get_numasks(idx);
	info->nattrs += NETBURST_MODS_COUNT;

	return PFM_SUCCESS;
}

static int
pfm_netburst_validate_table(void *this, FILE *fp)
{
	pfmlib_pmu_t *pmu = this;
	const netburst_entry_t *pe = netburst_events;
	const char *name =  pmu->name;
	int i, j, noname, ndfl;
	int error = 0;

	for(i=0; i < pmu->pme_count; i++) {

		if (!pe[i].name) {
			fprintf(fp, "pmu: %s event%d: :: no name (prev event was %s)\n", pmu->name, i,
			i > 1 ? pe[i-1].name : "??");
			error++;
		}

		if (!pe[i].desc) {
			fprintf(fp, "pmu: %s event%d: %s :: no description\n", name, i, pe[i].name);
			error++;
		}

		noname = ndfl = 0;

		/* name = NULL is end-marker, veryfy there is at least one */
		for(j= 0; j < EVENT_MASK_BITS; j++) {

			if (!pe[i].event_masks[j].name)
				noname++;

			if (pe[i].event_masks[j].name) {
				if (!pe[i].event_masks[j].desc) {
					fprintf(fp, "pmu: %s event%d:%s umask%d: %s :: no description\n", name, i, pe[i].name, j, pe[i].event_masks[j].name);
					error++;
				}
				if (pe[i].event_masks[j].bit >= (EVENT_MASK_BITS+4)) {
					fprintf(fp, "pmu: %s event%d:%s umask%d: %s :: invalid bit field\n", name, i, pe[i].name, j, pe[i].event_masks[j].name);
					error++;
				}

				if (pe[i].event_masks[j].flags & NETBURST_FL_DFL)
					ndfl++;
			}
		}
		if (ndfl > 1) {
			fprintf(fp, "pmu: %s event%d:%s :: more than one default umask\n", name, i, pe[i].name);
			error++;
		}
		if (!noname) {
			fprintf(fp, "pmu: %s event%d:%s :: no event mask end-marker\n", name, i, pe[i].name);
			error++;
		}
	}
	return error ? PFM_ERR_INVAL : PFM_SUCCESS;
}


static unsigned int
pfm_netburst_get_event_nattrs(void *this, int pidx)
{
	unsigned int nattrs;
	nattrs  = netburst_get_numasks(pidx);
	nattrs += NETBURST_MODS_COUNT;
	return nattrs;
}


pfmlib_pmu_t netburst_support = {
	.desc			= "Pentium4",
	.name			= "netburst",
	.pmu			= PFM_PMU_INTEL_NETBURST,
	.pme_count		= LIBPFM_ARRAY_SIZE(netburst_events) - 1,
	.type			= PFM_PMU_TYPE_CORE,
	.supported_plm		= INTEL_X86_PLM,
	.atdesc			= netburst_mods,
	.pe			= netburst_events,
	.max_encoding		= 3,
	.num_cntrs		= 18,

	.pmu_detect		= pfm_netburst_detect,
	.get_event_encoding[PFM_OS_NONE] = pfm_netburst_get_encoding,
	 PFMLIB_ENCODE_PERF(pfm_netburst_get_perf_encoding),
	.get_event_first	= pfm_netburst_get_event_first,
	.get_event_next		= pfm_netburst_get_event_next,
	.event_is_valid		= pfm_netburst_event_is_valid,
	.validate_table		= pfm_netburst_validate_table,
	.get_event_info		= pfm_netburst_get_event_info,
	.get_event_attr_info	= pfm_netburst_get_event_attr_info,
	.get_event_nattrs	= pfm_netburst_get_event_nattrs,
	 PFMLIB_VALID_PERF_PATTRS(pfm_netburst_perf_validate_pattrs),
};

pfmlib_pmu_t netburst_p_support = {
	.desc			= "Pentium4 (Prescott)",
	.name			= "netburst_p",
	.pmu			= PFM_PMU_INTEL_NETBURST_P,
	.pme_count		= LIBPFM_ARRAY_SIZE(netburst_events),
	.type			= PFM_PMU_TYPE_CORE,
	.supported_plm		= INTEL_X86_PLM,
	.atdesc			= netburst_mods,
	.pe			= netburst_events,
	.max_encoding		= 3,
	.num_cntrs		= 18,

	.pmu_detect		= pfm_netburst_detect_prescott,
	.get_event_encoding[PFM_OS_NONE] = pfm_netburst_get_encoding,
	 PFMLIB_ENCODE_PERF(pfm_netburst_get_perf_encoding),
	.get_event_first	= pfm_netburst_get_event_first,
	.get_event_next		= pfm_netburst_get_event_next,
	.event_is_valid		= pfm_netburst_event_is_valid,
	.validate_table		= pfm_netburst_validate_table,
	.get_event_info		= pfm_netburst_get_event_info,
	.get_event_attr_info	= pfm_netburst_get_event_attr_info,
	.get_event_nattrs	= pfm_netburst_get_event_nattrs,
	 PFMLIB_VALID_PERF_PATTRS(pfm_netburst_perf_validate_pattrs),
};
