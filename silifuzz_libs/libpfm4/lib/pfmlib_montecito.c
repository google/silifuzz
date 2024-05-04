/*
 * pfmlib_montecito.c : support for the Dual-Core Itanium2 processor
 *
 * Copyright (c) 2005-2006 Hewlett-Packard Development Company, L.P.
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
#include <sys/types.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* public headers */
#include <perfmon/pfmlib_montecito.h>

/* private headers */
#include "pfmlib_priv.h"		/* library private */
#include "pfmlib_priv_ia64.h"		/* architecture private */
#include "pfmlib_montecito_priv.h"	/* PMU private */
#include "montecito_events.h"		/* PMU private */

#define is_ear(i)	event_is_ear(montecito_pe+(i))
#define is_ear_tlb(i)	event_is_ear_tlb(montecito_pe+(i))
#define is_ear_alat(i)	event_is_ear_alat(montecito_pe+(i))
#define is_ear_cache(i)	event_is_ear_cache(montecito_pe+(i))
#define is_iear(i)	event_is_iear(montecito_pe+(i))
#define is_dear(i)	event_is_dear(montecito_pe+(i))
#define is_etb(i)	event_is_etb(montecito_pe+(i))
#define has_opcm(i)	event_opcm_ok(montecito_pe+(i))
#define has_iarr(i)	event_iarr_ok(montecito_pe+(i))
#define has_darr(i)	event_darr_ok(montecito_pe+(i))
#define has_all(i)	event_all_ok(montecito_pe+(i))
#define has_mesi(i)	event_mesi_ok(montecito_pe+(i))

#define evt_use_opcm(e)		((e)->pfp_mont_opcm1.opcm_used != 0 || (e)->pfp_mont_opcm2.opcm_used !=0)
#define evt_use_irange(e)	((e)->pfp_mont_irange.rr_used)
#define evt_use_drange(e)	((e)->pfp_mont_drange.rr_used)

#define evt_grp(e)	(int)montecito_pe[e].pme_qualifiers.pme_qual.pme_group
#define evt_set(e)	(int)montecito_pe[e].pme_qualifiers.pme_qual.pme_set
#define evt_umask(e)	montecito_pe[e].pme_umask
#define evt_type(e)	(int)montecito_pe[e].pme_type
#define evt_caf(e)	(int)montecito_pe[e].pme_caf

#define FINE_MODE_BOUNDARY_BITS	16
#define FINE_MODE_MASK		~((1U<<FINE_MODE_BOUNDARY_BITS)-1)

/* let's define some handy shortcuts! */
#define pmc_plm		pmc_mont_counter_reg.pmc_plm
#define pmc_ev		pmc_mont_counter_reg.pmc_ev
#define pmc_oi		pmc_mont_counter_reg.pmc_oi
#define pmc_pm		pmc_mont_counter_reg.pmc_pm
#define pmc_es		pmc_mont_counter_reg.pmc_es
#define pmc_umask	pmc_mont_counter_reg.pmc_umask
#define pmc_thres	pmc_mont_counter_reg.pmc_thres
#define pmc_all		pmc_mont_counter_reg.pmc_all
#define pmc_ism		pmc_mont_counter_reg.pmc_ism
#define pmc_m		pmc_mont_counter_reg.pmc_m
#define pmc_e		pmc_mont_counter_reg.pmc_e
#define pmc_s		pmc_mont_counter_reg.pmc_s
#define pmc_i		pmc_mont_counter_reg.pmc_i

#define UNEXISTING_SET	0xff

static char * pfm_mont_get_event_name(unsigned int i);
/*
 * Description of the PMC register mappings use by
 * this module (as reported in pfmlib_reg_t.reg_num):
 *
 * 0 -> PMC0
 * 1 -> PMC1
 * n -> PMCn
 *
 * The following are in the model specific rr_br[]:
 * IBR0 -> 0
 * IBR1 -> 1
 * ...
 * IBR7 -> 7
 * DBR0 -> 0
 * DBR1 -> 1
 * ...
 * DBR7 -> 7
 *
 * We do not use a mapping table, instead we make up the
 * values on the fly given the base.
 */

static int
pfm_mont_detect(void)
{
	int tmp;
	int ret = PFMLIB_ERR_NOTSUPP;

	tmp = pfm_ia64_get_cpu_family();
	if (tmp == 0x20) {
		ret = PFMLIB_SUCCESS;
	}
	return ret;
}

/*
 * Check the event for incompatibilities. This is useful
 * for L1D and L2D related events. Due to wire limitations,
 * some caches events are separated into sets. There
 * are 6 sets for the L1D cache group and 8 sets for L2D group.
 * It is NOT possible to simultaneously measure events from
 * differents sets for L1D. For instance, you cannot
 * measure events from set0 and set1 in L1D cache group. The L2D
 * group allows up to two different sets to be active at the same
 * time. The first set is selected by the event in PMC4 and the second
 * set by the event in PMC6. Once the set is selected for PMC4,
 * the same set is locked for PMC5 and PMC8. Similarly, once the
 * set is selected for PMC6, the same set is locked for PMC7 and 
 * PMC9.
 *
 * This function verifies that only one set of L1D is selected
 * and that no more than 2 sets are selected for L2D
 */
static int
check_cross_groups(pfmlib_input_param_t *inp, unsigned int *l1d_event, 
		unsigned long *l2d_set1_mask, unsigned long *l2d_set2_mask)
{
	int g, s, s1, s2;
	unsigned int cnt = inp->pfp_event_count;
	pfmlib_event_t *e = inp->pfp_events;
	unsigned int i, j;
	unsigned long l2d_mask1 = 0, l2d_mask2 = 0;
	unsigned int l1d_event_idx = UNEXISTING_SET;

	/*
	 * Let check the L1D constraint first
	 *
	 * There is no umask restriction for this group
	 */
	for (i=0; i < cnt; i++) {
		g = evt_grp(e[i].event);
		s = evt_set(e[i].event);

		if (g != PFMLIB_MONT_EVT_L1D_CACHE_GRP) continue;
		DPRINT("i=%u g=%d s=%d\n", i, g, s);
		l1d_event_idx = i;
		for (j=i+1; j < cnt; j++) {
			if (evt_grp(e[j].event) != g) continue;
			/*
			 * if there is another event from the same group
			 * but with a different set, then we return an error
			 */
			if (evt_set(e[j].event) != s) return PFMLIB_ERR_EVTSET;
		}
	}

	/*
	 * Check that we have only up to two distinct 
	 * sets for L2D
	 */
	s1 = s2 = -1;
	for (i=0; i < cnt; i++) {
		g = evt_grp(e[i].event);

		if (g != PFMLIB_MONT_EVT_L2D_CACHE_GRP) continue;

		s = evt_set(e[i].event); 

		/*
		 * we have seen this set before, continue
		 */
		if (s1 == s) {
			l2d_mask1 |= 1UL << i;
			continue;
		}
		if (s2 == s) {
			l2d_mask2 |= 1UL << i;
			continue;
		}
		/*
		 * record first of second set seen
		 */
		if (s1 == -1) {
			s1 = s;
			l2d_mask1 |= 1UL << i;
		} else if (s2 == -1) {
			s2 = s;
			l2d_mask2 |= 1UL << i;
		} else {
			/* 
			 * found a third set, that's not possible
			 */
			return PFMLIB_ERR_EVTSET;
		}
	}
	*l1d_event     = l1d_event_idx;
	*l2d_set1_mask = l2d_mask1;
	*l2d_set2_mask = l2d_mask2;

	return PFMLIB_SUCCESS;
}

/*
 * Certain prefetch events must be treated specially when instruction range restriction
 * is used because they can only be constrained by IBRP1 in fine-mode. Other events
 * will use IBRP0 if tagged as a demand fetch OR IBPR1 if tagged as a prefetch match.
 *
 * Events which can be qualified by the two pairs depending on their tag:
 * 	- ISB_BUNPAIRS_IN
 * 	- L1I_FETCH_RAB_HIT
 *	- L1I_FETCH_ISB_HIT
 * 	- L1I_FILLS
 *
 * This function returns the number of qualifying prefetch events found
 */
static int prefetch_events[]={
	PME_MONT_L1I_PREFETCHES,
	PME_MONT_L1I_STRM_PREFETCHES,
	PME_MONT_L2I_PREFETCHES
};
#define NPREFETCH_EVENTS	sizeof(prefetch_events)/sizeof(int)

static int prefetch_dual_events[]=
{
 PME_MONT_ISB_BUNPAIRS_IN,
 PME_MONT_L1I_FETCH_RAB_HIT,
 PME_MONT_L1I_FETCH_ISB_HIT,
 PME_MONT_L1I_FILLS
};
#define NPREFETCH_DUAL_EVENTS	sizeof(prefetch_dual_events)/sizeof(int)

/*
 * prefetch events must use IBRP1, unless they are dual and the user specified
 * PFMLIB_MONT_IRR_DEMAND_FETCH in rr_flags
 */
static int
check_prefetch_events(pfmlib_input_param_t *inp, pfmlib_mont_input_rr_t *irr, unsigned int *count, int *base_idx, int *dup)
{
	int code;
	int prefetch_codes[NPREFETCH_EVENTS];
	int prefetch_dual_codes[NPREFETCH_DUAL_EVENTS];
	unsigned int i, j;
	int c, flags;
	int found = 0, found_ibrp0 = 0, found_ibrp1 = 0;

	flags = irr->rr_flags & (PFMLIB_MONT_IRR_DEMAND_FETCH|PFMLIB_MONT_IRR_PREFETCH_MATCH);

	for(i=0; i < NPREFETCH_EVENTS; i++) {
		pfm_get_event_code(prefetch_events[i], &code);
		prefetch_codes[i] = code;
	}

	for(i=0; i < NPREFETCH_DUAL_EVENTS; i++) {
		pfm_get_event_code(prefetch_dual_events[i], &code);
		prefetch_dual_codes[i] = code;
	}

	for(i=0; i < inp->pfp_event_count; i++) {
		pfm_get_event_code(inp->pfp_events[i].event, &c);

		for(j=0; j < NPREFETCH_EVENTS; j++) {
			if (c == prefetch_codes[j]) {
				found++;
				found_ibrp1++;
			}
		}
		/*
		 * for the dual events, users must specify one or both of the
		 * PFMLIB_MONT_IRR_DEMAND_FETCH or PFMLIB_MONT_IRR_PREFETCH_MATCH
		 */
		for(j=0; j < NPREFETCH_DUAL_EVENTS; j++) {
			if (c == prefetch_dual_codes[j]) {
				found++;
				if (flags == 0)
					return PFMLIB_ERR_IRRFLAGS;
				if (flags & PFMLIB_MONT_IRR_DEMAND_FETCH)
					found_ibrp0++;
				if (flags & PFMLIB_MONT_IRR_PREFETCH_MATCH)
					found_ibrp1++;
			}
		}
	}
	*count =  found;
	*dup   = 0;

	/*
	 * if both found_ibrp0 and found_ibrp1 > 0, then we need to duplicate
	 * the range in ibrp0 to ibrp1.
	 */
	if (found) {
		*base_idx = found_ibrp0 ? 0 : 2;
		if (found_ibrp1 && found_ibrp0)
			*dup = 1;
	}
	return 0;
}

/*
 * look for CPU_OP_CYCLES_QUAL
 * Return:
 * 	1 if found
 * 	0 otherwise
 */
static int
has_cpu_cycles_qual(pfmlib_input_param_t *inp)
{
	unsigned int i;
	int code, c;

	pfm_get_event_code(PME_MONT_CPU_OP_CYCLES_QUAL, &code);

	for(i=0; i < inp->pfp_event_count; i++) {
		pfm_get_event_code(inp->pfp_events[i].event, &c);
		if (c == code)
			return 1;
	}
	return 0;
}

/*
 * IA64_INST_RETIRED (and subevents) is the only event which can be measured on all
 * 4 IBR when non-fine mode is not possible.
 *
 * This function returns:
 * 	- the number of events match the IA64_INST_RETIRED code
 * 	- in retired_mask to bottom 4 bits indicates which of the 4 INST_RETIRED event
 * 	is present
 */
static unsigned int
check_inst_retired_events(pfmlib_input_param_t *inp, unsigned long *retired_mask)
{
	int code;
	int c;
	unsigned int i, count, found = 0;
	unsigned long umask, mask;

	pfm_get_event_code(PME_MONT_IA64_INST_RETIRED, &code);

	count = inp->pfp_event_count;
	mask  = 0;
	for(i=0; i < count; i++) {
		pfm_get_event_code(inp->pfp_events[i].event, &c);
		if (c == code)  {
			pfm_mont_get_event_umask(inp->pfp_events[i].event, &umask);
			switch(umask) {
				case 0: mask |= 1;
					break;
				case 1: mask |= 2;
					break;
				case 2: mask |= 4;
					break;
				case 3: mask |= 8;
					break;
			}
			found++;
		}
	}
	if (retired_mask) *retired_mask = mask;
	return found;
}

static int
check_fine_mode_possible(pfmlib_mont_input_rr_t *rr, int n)
{
	pfmlib_mont_input_rr_desc_t *lim = rr->rr_limits;
	int i;

	for(i=0; i < n; i++) {
		if ((lim[i].rr_start & FINE_MODE_MASK) != (lim[i].rr_end & FINE_MODE_MASK))
			return 0;
	}
	return 1;
}

/*
 * mode = 0 -> check code (enforce bundle alignment)
 * mode = 1 -> check data
 */
static int
check_intervals(pfmlib_mont_input_rr_t *irr, int mode, unsigned int *n_intervals)
{
	unsigned int i;
	pfmlib_mont_input_rr_desc_t *lim = irr->rr_limits;

	for(i=0; i < 4; i++) {
		/* end marker */
		if (lim[i].rr_start == 0 && lim[i].rr_end == 0) break;

		/* invalid entry */
		if (lim[i].rr_start >= lim[i].rr_end) return PFMLIB_ERR_IRRINVAL;

		if (mode == 0 && (lim[i].rr_start & 0xf || lim[i].rr_end & 0xf))
			return PFMLIB_ERR_IRRALIGN;
	}
	*n_intervals = i;
	return PFMLIB_SUCCESS;
}

/*
 * It is not possible to measure more than one of the
 * L2D_OZQ_CANCELS0, L2D_OZQ_CANCELS1 at the same time.
 */

static int cancel_events[]=
{
	PME_MONT_L2D_OZQ_CANCELS0_ACQ,
	PME_MONT_L2D_OZQ_CANCELS1_ANY
};
#define NCANCEL_EVENTS	sizeof(cancel_events)/sizeof(int)

static int
check_cancel_events(pfmlib_input_param_t *inp)
{
	unsigned int i, j, count;
	int code;
	int cancel_codes[NCANCEL_EVENTS];
	int idx = -1;

	for(i=0; i < NCANCEL_EVENTS; i++) {
		pfm_get_event_code(cancel_events[i], &code);
		cancel_codes[i] = code;
	}
	count = inp->pfp_event_count;
	for(i=0; i < count; i++) {
		for (j=0; j < NCANCEL_EVENTS; j++) {
			pfm_get_event_code(inp->pfp_events[i].event, &code);
			if (code == cancel_codes[j]) {
				if (idx != -1) {
					return PFMLIB_ERR_INVAL;
				}
				idx = inp->pfp_events[i].event;
			}
		}
	}
	return PFMLIB_SUCCESS;
}

/*
 * Automatically dispatch events to corresponding counters following constraints.
 */
static unsigned int l2d_set1_cnts[]={ 4, 5, 8 };
static unsigned int l2d_set2_cnts[]={ 6, 7, 9 };

static int
pfm_mont_dispatch_counters(pfmlib_input_param_t *inp, pfmlib_mont_input_param_t *mod_in, pfmlib_output_param_t *outp)
{
	pfmlib_mont_input_param_t *param = mod_in;
	pfm_mont_pmc_reg_t reg;
	pfmlib_event_t *e;
	pfmlib_reg_t *pc, *pd;
	pfmlib_regmask_t avail_cntrs, impl_cntrs;
	unsigned int i,j, k, max_cnt;
	unsigned int assign[PMU_MONT_NUM_COUNTERS];
	unsigned int m, cnt;
	unsigned int l1d_set;
	unsigned long l2d_set1_mask, l2d_set2_mask, evt_mask, mesi;
	unsigned long not_assigned_events, cnt_mask;
	int l2d_set1_p, l2d_set2_p;
	int ret;

	e      = inp->pfp_events;
	pc     = outp->pfp_pmcs;
	pd     = outp->pfp_pmds;
	cnt    = inp->pfp_event_count;

	if (PFMLIB_DEBUG())
		for (m=0; m < cnt; m++) {
			DPRINT("ev[%d]=%s counters=0x%lx\n", m, montecito_pe[e[m].event].pme_name,
				montecito_pe[e[m].event].pme_counters);
		}

	if (cnt > PMU_MONT_NUM_COUNTERS) return PFMLIB_ERR_TOOMANY;

	l1d_set = UNEXISTING_SET;
	ret = check_cross_groups(inp, &l1d_set, &l2d_set1_mask, &l2d_set2_mask);
	if (ret != PFMLIB_SUCCESS) return ret;

	ret = check_cancel_events(inp);
	if (ret != PFMLIB_SUCCESS) return ret;

	/*
	 * at this point, we know that:
	 * 	- we have at most 1 L1D set
	 * 	- we have at most 2 L2D sets
	 * 	- cancel events are compatible
	 */

	DPRINT("l1d_set=%u l2d_set1_mask=0x%lx l2d_set2_mask=0x%lx\n", l1d_set, l2d_set1_mask, l2d_set2_mask);

	/*
	 * first, place L1D cache event in PMC5
	 *
	 * this is the strongest constraint
	 */
	pfm_get_impl_counters(&impl_cntrs);
	pfm_regmask_andnot(&avail_cntrs, &impl_cntrs, &inp->pfp_unavail_pmcs);
	not_assigned_events = 0;

	DPRINT("avail_cntrs=0x%lx\n", avail_cntrs.bits[0]);

	/*
	 * we do not check ALL_THRD here because at least
	 * one event has to be in PMC5 for this group
	 */
	if (l1d_set != UNEXISTING_SET) {

		if (!pfm_regmask_isset(&avail_cntrs, 5))
			return PFMLIB_ERR_NOASSIGN;

		assign[l1d_set] = 5;

		pfm_regmask_clr(&avail_cntrs, 5);
	}

	l2d_set1_p = l2d_set2_p = 0;

	/*
	 * assign L2D set1 and set2 counters
	 */
	for (i=0; i < cnt ; i++) {
			evt_mask = 1UL << i;
			/*
			 * place l2d set1 events. First 3 go to designated
			 * counters, the rest is placed elsewhere in the final
			 * pass
			 */
			if (l2d_set1_p < 3 && (l2d_set1_mask & evt_mask)) {
				assign[i] = l2d_set1_cnts[l2d_set1_p];

				if (!pfm_regmask_isset(&avail_cntrs, assign[i]))
					return PFMLIB_ERR_NOASSIGN;

				pfm_regmask_clr(&avail_cntrs, assign[i]);
				l2d_set1_p++;
				continue;
			}
			/*
			 * same as above but for l2d set2
			 */
			if (l2d_set2_p  < 3 && (l2d_set2_mask & evt_mask)) {
				assign[i] = l2d_set2_cnts[l2d_set2_p];

				if (!pfm_regmask_isset(&avail_cntrs, assign[i]))
					return PFMLIB_ERR_NOASSIGN;

				pfm_regmask_clr(&avail_cntrs, assign[i]);
				l2d_set2_p++;
				continue;
			}
			/*
			 * if not l2d nor l1d, then defer placement until final pass
			 */
			if (i != l1d_set)
				not_assigned_events |= evt_mask;

			DPRINT("phase 1: i=%u avail_cntrs=0x%lx l2d_set1_p=%d l2d_set2_p=%d not_assigned=0x%lx\n", 
				i,
				avail_cntrs.bits[0],
				l2d_set1_p,
				l2d_set2_p,
				not_assigned_events);
	}
	/*
	 * assign BUS_* ER_* events (work only in PMC4-PMC9)
	 */
	evt_mask = not_assigned_events;
	for (i=0; evt_mask ; i++, evt_mask >>=1) {

		if ((evt_mask & 0x1) == 0)
			continue;

		cnt_mask = montecito_pe[e[i].event].pme_counters;
		/*
		 * only interested in events with restricted set of counters
		 */
		if (cnt_mask == 0xfff0)
			continue;

		for(j=0; cnt_mask; j++, cnt_mask >>=1) {
			if ((cnt_mask & 0x1) == 0) 
				continue;

			DPRINT("phase 2: i=%d j=%d cnt_mask=0x%lx avail_cntrs=0x%lx not_assigned_evnts=0x%lx\n",
				i, j, cnt_mask, avail_cntrs.bits[0], not_assigned_events);

			if (!pfm_regmask_isset(&avail_cntrs, j))
				continue;

			assign[i] = j;
			not_assigned_events &= ~(1UL << i);
			pfm_regmask_clr(&avail_cntrs, j);
			break;
		}
		if (cnt_mask == 0)
			return PFMLIB_ERR_NOASSIGN;
	}
	/*
	 * assign the rest of the events (no constraints)
	 */
	evt_mask = not_assigned_events;
	max_cnt = PMU_MONT_FIRST_COUNTER + PMU_MONT_NUM_COUNTERS;
	for (i=0, j=0; evt_mask ; i++, evt_mask >>=1) {

		DPRINT("phase 3a: i=%d j=%d evt_mask=0x%lx avail_cntrs=0x%lx not_assigned_evnts=0x%lx\n",
			i, j, evt_mask, avail_cntrs.bits[0], not_assigned_events);
		if ((evt_mask & 0x1) == 0)
			continue;

		while(j < max_cnt && !pfm_regmask_isset(&avail_cntrs, j)) {
			DPRINT("phase 3: i=%d j=%d evt_mask=0x%lx avail_cntrs=0x%lx not_assigned_evnts=0x%lx\n",
				i, j, evt_mask, avail_cntrs.bits[0], not_assigned_events);
			j++;
		}

		if (j == max_cnt)
			return PFMLIB_ERR_NOASSIGN;

		assign[i] = j;
		j++;
	}

	for (j=0; j < cnt ; j++ ) {
		mesi = 0;

		/*
		 * XXX: we do not support .all placement just yet
		 */
		if (param && param->pfp_mont_counters[j].flags & PFMLIB_MONT_FL_EVT_ALL_THRD) {
			DPRINT(".all mode is not yet supported by libpfm\n");
			return PFMLIB_ERR_NOTSUPP;
		}

		if (has_mesi(e[j].event)) {
			for(k=0;k< e[j].num_masks; k++) {
				mesi |= 1UL << e[j].unit_masks[k];
			}
			/* by default we capture everything */
			if (mesi == 0)
				mesi = 0xf;
		}
		reg.pmc_val    = 0; /* clear all, bits 26-27 must be zero for proper operations */
		/* if plm is 0, then assume not specified per-event and use default */
		reg.pmc_plm    = inp->pfp_events[j].plm ? inp->pfp_events[j].plm : inp->pfp_dfl_plm;
		reg.pmc_oi     = 0; /* let the user/OS deal with this field */
		reg.pmc_pm     = inp->pfp_flags & PFMLIB_PFP_SYSTEMWIDE ? 1 : 0;
		reg.pmc_thres  = param ? param->pfp_mont_counters[j].thres: 0;
		reg.pmc_ism    = 0x2; /* force IA-64 mode */
		reg.pmc_umask  = is_ear(e[j].event) ? 0x0 : montecito_pe[e[j].event].pme_umask;
		reg.pmc_es     = montecito_pe[e[j].event].pme_code;
		reg.pmc_all    = 0; /* XXX force self for now */
		reg.pmc_m      = (mesi>>3) & 0x1;
		reg.pmc_e      = (mesi>>2) & 0x1;
		reg.pmc_s      = (mesi>>1) & 0x1;
		reg.pmc_i      =  mesi     & 0x1;
		/*
		 * Note that we don't force PMC4.pmc_ena = 1 because the kernel takes care of this for us.
		 * This way we don't have to program something in PMC4 even when we don't use it
		 */
		pc[j].reg_num     = assign[j];
		pc[j].reg_value   = reg.pmc_val;
		pc[j].reg_addr    = pc[j].reg_alt_addr = assign[j];

		pd[j].reg_num  = assign[j];
		pd[j].reg_addr = pd[j].reg_alt_addr = assign[j];

		__pfm_vbprintf("[PMC%u(pmc%u)=0x%06lx m=%d e=%d s=%d i=%d thres=%d all=%d es=0x%02x plm=%d umask=0x%x pm=%d ism=0x%x oi=%d] %s\n",
				assign[j],
				assign[j],
				reg.pmc_val,
				reg.pmc_m,
				reg.pmc_e,
				reg.pmc_s,
				reg.pmc_i,
				reg.pmc_thres,
				reg.pmc_all,
				reg.pmc_es,reg.pmc_plm,
				reg.pmc_umask, reg.pmc_pm,
				reg.pmc_ism,
				reg.pmc_oi,
				montecito_pe[e[j].event].pme_name);
		__pfm_vbprintf("[PMD%u(pmd%u)]\n", pd[j].reg_num, pd[j].reg_num);
	}
	/* number of PMC registers programmed */
	outp->pfp_pmc_count = cnt;
	outp->pfp_pmd_count = cnt;

	return PFMLIB_SUCCESS;
}

static int
pfm_dispatch_iear(pfmlib_input_param_t *inp, pfmlib_mont_input_param_t *mod_in, pfmlib_output_param_t *outp)
{
	pfm_mont_pmc_reg_t reg;
	pfmlib_mont_input_param_t *param = mod_in;
	pfmlib_reg_t *pc, *pd;
	pfmlib_mont_input_param_t fake_param;
	unsigned int pos1, pos2;
	unsigned int i, count;

	pc = outp->pfp_pmcs;
	pd = outp->pfp_pmds;
	pos1 = outp->pfp_pmc_count;
	pos2 = outp->pfp_pmd_count;
	count = inp->pfp_event_count;

	for (i=0; i < count; i++) {
		if (is_iear(inp->pfp_events[i].event)) break;
	}

	if (param == NULL || param->pfp_mont_iear.ear_used == 0) {

		/*
		 * case 3: no I-EAR event, no (or nothing) in param->pfp_mont_iear.ear_used
		 */
		if (i == count) return PFMLIB_SUCCESS;

		memset(&fake_param, 0, sizeof(fake_param));
		param = &fake_param;

		/*
		 * case 1: extract all information for event (name)
		 */
		pfm_mont_get_ear_mode(inp->pfp_events[i].event, &param->pfp_mont_iear.ear_mode);

		param->pfp_mont_iear.ear_umask = evt_umask(inp->pfp_events[i].event);

		DPRINT("I-EAR event with no info\n");
	}

	/*
	 * case 2: ear_used=1, event is defined, we use the param info as it is more precise
	 * case 4: ear_used=1, no event (free running I-EAR), use param info
	 */
	reg.pmc_val = 0;

	if (param->pfp_mont_iear.ear_mode == PFMLIB_MONT_EAR_TLB_MODE) {
		/* if plm is 0, then assume not specified per-event and use default */
		reg.pmc37_mont_tlb_reg.iear_plm     = param->pfp_mont_iear.ear_plm ? param->pfp_mont_iear.ear_plm : inp->pfp_dfl_plm;
		reg.pmc37_mont_tlb_reg.iear_pm      = inp->pfp_flags & PFMLIB_PFP_SYSTEMWIDE ? 1 : 0;
		reg.pmc37_mont_tlb_reg.iear_ct      = 0x0;
		reg.pmc37_mont_tlb_reg.iear_umask   = param->pfp_mont_iear.ear_umask;
	} else if (param->pfp_mont_iear.ear_mode == PFMLIB_MONT_EAR_CACHE_MODE) {
		/* if plm is 0, then assume not specified per-event and use default */
		reg.pmc37_mont_cache_reg.iear_plm   = param->pfp_mont_iear.ear_plm ? param->pfp_mont_iear.ear_plm : inp->pfp_dfl_plm;
		reg.pmc37_mont_cache_reg.iear_pm    = inp->pfp_flags & PFMLIB_PFP_SYSTEMWIDE ? 1 : 0;
		reg.pmc37_mont_cache_reg.iear_ct    = 0x1;
		reg.pmc37_mont_cache_reg.iear_umask = param->pfp_mont_iear.ear_umask;
	} else {
		DPRINT("ALAT mode not supported in I-EAR mode\n");
		return PFMLIB_ERR_INVAL;
	}
	if (pfm_regmask_isset(&inp->pfp_unavail_pmcs, 37))
		return PFMLIB_ERR_NOASSIGN;

	pc[pos1].reg_num     = 37; /* PMC37 is I-EAR config register */
	pc[pos1].reg_value   = reg.pmc_val;
	pc[pos1].reg_addr  = pc[pos1].reg_addr = 37;
	pos1++;

	pd[pos2].reg_num  = 34;
	pd[pos2].reg_addr = pd[pos2].reg_alt_addr = 34; 
	pos2++;
	pd[pos2].reg_num  = 35;
	pd[pos2].reg_addr = pd[pos2].reg_alt_addr = 35; 
	pos2++;

	if (param->pfp_mont_iear.ear_mode == PFMLIB_MONT_EAR_TLB_MODE) {
		__pfm_vbprintf("[PMC37(pmc37)=0x%lx ctb=tlb plm=%d pm=%d umask=0x%x]\n",
			reg.pmc_val,
			reg.pmc37_mont_tlb_reg.iear_plm,
			reg.pmc37_mont_tlb_reg.iear_pm,
			reg.pmc37_mont_tlb_reg.iear_umask);
	} else {
		__pfm_vbprintf("[PMC37(pmc37)=0x%lx ctb=cache plm=%d pm=%d umask=0x%x]\n",
			reg.pmc_val,
			reg.pmc37_mont_cache_reg.iear_plm,
			reg.pmc37_mont_cache_reg.iear_pm,
			reg.pmc37_mont_cache_reg.iear_umask);
	}
	__pfm_vbprintf("[PMD34(pmd34)]\n[PMD35(pmd35)\n");

	/* update final number of entries used */
	outp->pfp_pmc_count = pos1;
	outp->pfp_pmd_count = pos2;

	return PFMLIB_SUCCESS;
}

static int
pfm_dispatch_dear(pfmlib_input_param_t *inp, pfmlib_mont_input_param_t *mod_in, pfmlib_output_param_t *outp)
{
	pfm_mont_pmc_reg_t reg;
	pfmlib_mont_input_param_t *param = mod_in;
	pfmlib_reg_t *pc, *pd;
	pfmlib_mont_input_param_t fake_param;
	unsigned int pos1, pos2;
	unsigned int i, count;

	pc = outp->pfp_pmcs;
	pd = outp->pfp_pmds;
	pos1 = outp->pfp_pmc_count;
	pos2 = outp->pfp_pmd_count;

	count = inp->pfp_event_count;
	for (i=0; i < count; i++) {
		if (is_dear(inp->pfp_events[i].event)) break;
	}

	if (param == NULL || param->pfp_mont_dear.ear_used == 0) {

		/*
		 * case 3: no D-EAR event, no (or nothing) in param->pfp_mont_dear.ear_used
		 */
		if (i == count) return PFMLIB_SUCCESS;

		memset(&fake_param, 0, sizeof(fake_param));
		param = &fake_param;

		/*
		 * case 1: extract all information for event (name)
		 */
		pfm_mont_get_ear_mode(inp->pfp_events[i].event, &param->pfp_mont_dear.ear_mode);

		param->pfp_mont_dear.ear_umask = evt_umask(inp->pfp_events[i].event);

		DPRINT("D-EAR event with no info\n");
	}

	/* sanity check on the mode */
	if (   param->pfp_mont_dear.ear_mode != PFMLIB_MONT_EAR_CACHE_MODE
	    && param->pfp_mont_dear.ear_mode != PFMLIB_MONT_EAR_TLB_MODE
	    && param->pfp_mont_dear.ear_mode != PFMLIB_MONT_EAR_ALAT_MODE)
		return PFMLIB_ERR_INVAL;

	/*
	 * case 2: ear_used=1, event is defined, we use the param info as it is more precise
	 * case 4: ear_used=1, no event (free running D-EAR), use param info
	 */
	reg.pmc_val = 0;

	/* if plm is 0, then assume not specified per-event and use default */
	reg.pmc40_mont_reg.dear_plm   = param->pfp_mont_dear.ear_plm ? param->pfp_mont_dear.ear_plm : inp->pfp_dfl_plm;
	reg.pmc40_mont_reg.dear_pm    = inp->pfp_flags & PFMLIB_PFP_SYSTEMWIDE ? 1 : 0;
	reg.pmc40_mont_reg.dear_mode  = param->pfp_mont_dear.ear_mode;
	reg.pmc40_mont_reg.dear_umask = param->pfp_mont_dear.ear_umask;
	reg.pmc40_mont_reg.dear_ism   = 0x2; /* force IA-64 mode */

	if (pfm_regmask_isset(&inp->pfp_unavail_pmcs, 40))
		return PFMLIB_ERR_NOASSIGN;

	pc[pos1].reg_num     = 40;  /* PMC11 is D-EAR config register */
	pc[pos1].reg_value   = reg.pmc_val;
	pc[pos1].reg_addr  = pc[pos1].reg_alt_addr = 40;
	pos1++;

	pd[pos2].reg_num  = 32;
	pd[pos2].reg_addr = pd[pos2].reg_alt_addr = 32; 
	pos2++;
	pd[pos2].reg_num  = 33;
	pd[pos2].reg_addr = pd[pos2].reg_alt_addr = 33; 
	pos2++;
	pd[pos2].reg_num  = 36;
	pd[pos2].reg_addr = pd[pos2].reg_alt_addr = 36; 
	pos2++;

	__pfm_vbprintf("[PMC40(pmc40)=0x%lx mode=%s plm=%d pm=%d ism=0x%x umask=0x%x]\n",
			reg.pmc_val,
			reg.pmc40_mont_reg.dear_mode == 0 ? "L1D" :
			(reg.pmc40_mont_reg.dear_mode == 1 ? "L1DTLB" : "ALAT"),
			reg.pmc40_mont_reg.dear_plm,	
			reg.pmc40_mont_reg.dear_pm,
			reg.pmc40_mont_reg.dear_ism,
			reg.pmc40_mont_reg.dear_umask);
	__pfm_vbprintf("[PMD32(pmd32)]\n[PMD33(pmd33)\nPMD36(pmd36)\n");

	/* update final number of entries used */
	outp->pfp_pmc_count = pos1;
	outp->pfp_pmd_count = pos2;

	return PFMLIB_SUCCESS;
}

static int
pfm_dispatch_opcm(pfmlib_input_param_t *inp, pfmlib_mont_input_param_t *mod_in, pfmlib_output_param_t *outp, pfmlib_mont_output_param_t *mod_out)
{
	pfmlib_mont_input_param_t *param = mod_in;
	pfmlib_reg_t *pc = outp->pfp_pmcs;
	pfm_mont_pmc_reg_t reg1, reg2, pmc36;
	unsigned int i, has_1st_pair, has_2nd_pair, count;
	unsigned int pos = outp->pfp_pmc_count;
	int used_pmc32, used_pmc34;

	if (param == NULL) return PFMLIB_SUCCESS;

#define PMC36_DFL_VAL 0xfffffff0


	/* 
	 * mandatory default value for PMC36 as described in the documentation
	 * all monitoring is opcode constrained. Better make sure the match/mask
	 * is set to match everything! It looks weird for the default value!
	 */
	pmc36.pmc_val = PMC36_DFL_VAL;

	reg1.pmc_val = 0x030f01ffffffffff;
	reg2.pmc_val = 0;

	used_pmc32 = param->pfp_mont_opcm1.opcm_used;
	used_pmc34 = param->pfp_mont_opcm2.opcm_used;

	/*
	 * check in any feature is used.
	 * PMC36 must be setup when opcode matching is used OR when code range restriction is used
	 */
	if (used_pmc32 == 0 && used_pmc34 == 0 && param->pfp_mont_irange.rr_used == 0)
		return 0;

	/*
	 * check for rr_nbr_used to make sure that the range request produced something on output
	 */
	if (used_pmc32 || (param->pfp_mont_irange.rr_used && mod_out->pfp_mont_irange.rr_nbr_used) ) {
		/*
		 * if not used, ignore all bits
		 */
		if (used_pmc32) {
			reg1.pmc32_34_mont_reg.opcm_mask  = param->pfp_mont_opcm1.opcm_mask;
			reg1.pmc32_34_mont_reg.opcm_b     = param->pfp_mont_opcm1.opcm_b;
			reg1.pmc32_34_mont_reg.opcm_f     = param->pfp_mont_opcm1.opcm_f;
			reg1.pmc32_34_mont_reg.opcm_i     = param->pfp_mont_opcm1.opcm_i;
			reg1.pmc32_34_mont_reg.opcm_m     = param->pfp_mont_opcm1.opcm_m;

			reg2.pmc33_35_mont_reg.opcm_match = param->pfp_mont_opcm1.opcm_match;
		} 

		if (param->pfp_mont_irange.rr_used) {
			reg1.pmc32_34_mont_reg.opcm_ig_ad = 0;
			reg1.pmc32_34_mont_reg.opcm_inv   = param->pfp_mont_irange.rr_flags & PFMLIB_MONT_RR_INV ? 1 : 0;
		} else {
			/* clear range restriction fields when none is used */
			reg1.pmc32_34_mont_reg.opcm_ig_ad = 1;
			reg1.pmc32_34_mont_reg.opcm_inv   = 0;
		}

		if (pfm_regmask_isset(&inp->pfp_unavail_pmcs, 32))
			return PFMLIB_ERR_NOASSIGN;

		pc[pos].reg_num     = 32;
		pc[pos].reg_value   = reg1.pmc_val;
		pc[pos].reg_addr  = pc[pos].reg_alt_addr = 32;
		pos++;

		/*
		 * will be constrained by PMC32
		 */
		if (used_pmc32) {
			if (pfm_regmask_isset(&inp->pfp_unavail_pmcs, 33))
				return PFMLIB_ERR_NOASSIGN;
			/*
			 * used pmc33 only when we have active opcode matching
			 */
			pc[pos].reg_num     = 33;
			pc[pos].reg_value   = reg2.pmc_val;
			pc[pos].reg_addr  = pc[pos].reg_alt_addr = 33;
			pos++;

			has_1st_pair = has_2nd_pair = 0;
			count        = inp->pfp_event_count;

			for(i=0; i < count; i++) {
				if (inp->pfp_events[i].event == PME_MONT_IA64_TAGGED_INST_RETIRED_IBRP0_PMC32_33) has_1st_pair=1;
				if (inp->pfp_events[i].event == PME_MONT_IA64_TAGGED_INST_RETIRED_IBRP2_PMC32_33) has_2nd_pair=1;
			}
			if (has_1st_pair || has_2nd_pair == 0) pmc36.pmc36_mont_reg.opcm_ch0_ig_opcm = 0;
			if (has_2nd_pair || has_1st_pair == 0) pmc36.pmc36_mont_reg.opcm_ch2_ig_opcm = 0;
		}

		__pfm_vbprintf("[PMC32(pmc32)=0x%lx m=%d i=%d f=%d b=%d mask=0x%lx inv=%d ig_ad=%d]\n",
				reg1.pmc_val,
				reg1.pmc32_34_mont_reg.opcm_m,
				reg1.pmc32_34_mont_reg.opcm_i,
				reg1.pmc32_34_mont_reg.opcm_f,
				reg1.pmc32_34_mont_reg.opcm_b,
				reg1.pmc32_34_mont_reg.opcm_mask,
				reg1.pmc32_34_mont_reg.opcm_inv,
				reg1.pmc32_34_mont_reg.opcm_ig_ad);
		if (used_pmc32)
			__pfm_vbprintf("[PMC33(pmc33)=0x%lx match=0x%lx]\n",
					reg2.pmc_val,
					reg2.pmc33_35_mont_reg.opcm_match);
	}

	/*
	 * will be constrained by PMC34
	 */
	if (used_pmc34) {
		reg1.pmc_val = 0x01ffffffffff; /* pmc34 default value */
		reg2.pmc_val = 0;

		reg1.pmc32_34_mont_reg.opcm_mask  = param->pfp_mont_opcm2.opcm_mask;
		reg1.pmc32_34_mont_reg.opcm_b     = param->pfp_mont_opcm2.opcm_b;
		reg1.pmc32_34_mont_reg.opcm_f     = param->pfp_mont_opcm2.opcm_f;
		reg1.pmc32_34_mont_reg.opcm_i     = param->pfp_mont_opcm2.opcm_i;
		reg1.pmc32_34_mont_reg.opcm_m     = param->pfp_mont_opcm2.opcm_m;

		reg2.pmc33_35_mont_reg.opcm_match = param->pfp_mont_opcm2.opcm_match;

		if (pfm_regmask_isset(&inp->pfp_unavail_pmcs, 34))
			return PFMLIB_ERR_NOASSIGN;

		if (pfm_regmask_isset(&inp->pfp_unavail_pmcs, 35))
			return PFMLIB_ERR_NOASSIGN;

		pc[pos].reg_num     = 34;
		pc[pos].reg_value   = reg1.pmc_val;
		pc[pos].reg_addr    = pc[pos].reg_alt_addr = 34;
		pos++;
		pc[pos].reg_num     = 35;
		pc[pos].reg_value   = reg2.pmc_val;
		pc[pos].reg_addr    = pc[pos].reg_alt_addr = 35;
		pos++;

		has_1st_pair = has_2nd_pair = 0;
		count        = inp->pfp_event_count;
		for(i=0; i < count; i++) {
			if (inp->pfp_events[i].event == PME_MONT_IA64_TAGGED_INST_RETIRED_IBRP1_PMC34_35) has_1st_pair=1;
			if (inp->pfp_events[i].event == PME_MONT_IA64_TAGGED_INST_RETIRED_IBRP3_PMC34_35) has_2nd_pair=1;
		}
		if (has_1st_pair || has_2nd_pair == 0) pmc36.pmc36_mont_reg.opcm_ch1_ig_opcm = 0;
		if (has_2nd_pair || has_1st_pair == 0) pmc36.pmc36_mont_reg.opcm_ch3_ig_opcm = 0;

		__pfm_vbprintf("[PMC34(pmc34)=0x%lx m=%d i=%d f=%d b=%d mask=0x%lx]\n",
				reg1.pmc_val,
				reg1.pmc32_34_mont_reg.opcm_m,
				reg1.pmc32_34_mont_reg.opcm_i,
				reg1.pmc32_34_mont_reg.opcm_f,
				reg1.pmc32_34_mont_reg.opcm_b,
				reg1.pmc32_34_mont_reg.opcm_mask);

		__pfm_vbprintf("[PMC35(pmc35)=0x%lx match=0x%lx]\n",
				reg2.pmc_val,
				reg2.pmc33_35_mont_reg.opcm_match);

	}
	if (pmc36.pmc_val != PMC36_DFL_VAL) {

		if (pfm_regmask_isset(&inp->pfp_unavail_pmcs, 36))
			return PFMLIB_ERR_NOASSIGN;

		pc[pos].reg_num     = 36;
		pc[pos].reg_value   = pmc36.pmc_val;
		pc[pos].reg_addr  = pc[pos].reg_alt_addr = 36;
		pos++;

		__pfm_vbprintf("[PMC36(pmc36)=0x%lx ch0_ig_op=%d ch1_ig_op=%d ch2_ig_op=%d ch3_ig_op=%d]\n",
				pmc36.pmc_val,
				pmc36.pmc36_mont_reg.opcm_ch0_ig_opcm,
				pmc36.pmc36_mont_reg.opcm_ch1_ig_opcm,
				pmc36.pmc36_mont_reg.opcm_ch2_ig_opcm,
				pmc36.pmc36_mont_reg.opcm_ch3_ig_opcm);
	}

	outp->pfp_pmc_count = pos;

	return PFMLIB_SUCCESS;
}

static int
pfm_dispatch_etb(pfmlib_input_param_t *inp, pfmlib_mont_input_param_t *mod_in, pfmlib_output_param_t *outp)
{
	pfmlib_event_t *e= inp->pfp_events;
	pfm_mont_pmc_reg_t reg;
	pfmlib_mont_input_param_t *param = mod_in;
	pfmlib_reg_t *pc, *pd;
	pfmlib_mont_input_param_t fake_param;
	int found_etb = 0, found_bad_dear = 0;
	int has_etb_param;
	unsigned int i, pos1, pos2;
	unsigned int count;

	pc = outp->pfp_pmcs;
	pd = outp->pfp_pmds;
	pos1 = outp->pfp_pmc_count;
	pos2 = outp->pfp_pmd_count;
	/*
	 * explicit ETB settings
	 */
	has_etb_param = param && param->pfp_mont_etb.etb_used;

	reg.pmc_val = 0UL;

	/*
	 * we need to scan all events looking for DEAR ALAT/TLB due to incompatibility.
	 * In this case PMC39 must be forced to zero
	 */
	count = inp->pfp_event_count;
	for (i=0; i < count; i++) {

		if (is_etb(e[i].event)) found_etb = 1;

		/*
		 * keep track of the first ETB event
		 */

		/* look only for DEAR TLB */
		if (is_dear(e[i].event) && (is_ear_tlb(e[i].event) || is_ear_alat(e[i].event))) {
			found_bad_dear = 1;
		}
	}

	DPRINT("found_etb=%d found_bar_dear=%d\n", found_etb, found_bad_dear);

	/*
	 * did not find D-EAR TLB/ALAT event, need to check param structure
	 */
	if (found_bad_dear == 0 && param && param->pfp_mont_dear.ear_used == 1) {
		if (   param->pfp_mont_dear.ear_mode == PFMLIB_MONT_EAR_TLB_MODE
		    || param->pfp_mont_dear.ear_mode == PFMLIB_MONT_EAR_ALAT_MODE)
			found_bad_dear = 1;
	}

	/*
	 * no explicit ETB event and no special case to deal with (cover part of case 3)
	 */
	if (found_etb == 0 && has_etb_param == 0 && found_bad_dear == 0) return PFMLIB_SUCCESS;

	if (has_etb_param == 0) {

		/*
		 * case 3: no ETB event, etb_used=0 but found_bad_dear=1, need to cleanup PMC12
		 */
		 if (found_etb == 0) goto assign_zero;

		/*
		 * case 1: we have a ETB event but no param, default setting is to capture
		 *         all branches.
		 */
		memset(&fake_param, 0, sizeof(fake_param));
		param = &fake_param;

		param->pfp_mont_etb.etb_tm  = 0x3; 	/* all branches */
		param->pfp_mont_etb.etb_ptm = 0x3; 	/* all branches */
		param->pfp_mont_etb.etb_ppm = 0x3; 	/* all branches */
		param->pfp_mont_etb.etb_brt = 0x0; 	/* all branches */

		DPRINT("ETB event with no info\n");
	}

	/*
	 * case 2: ETB event in the list, param provided
	 * case 4: no ETB event, param provided (free running mode)
	 */
	reg.pmc39_mont_reg.etbc_plm = param->pfp_mont_etb.etb_plm ? param->pfp_mont_etb.etb_plm : inp->pfp_dfl_plm;
	reg.pmc39_mont_reg.etbc_pm  = inp->pfp_flags & PFMLIB_PFP_SYSTEMWIDE ? 1 : 0;
	reg.pmc39_mont_reg.etbc_ds  = 0; /* 1 is reserved */
	reg.pmc39_mont_reg.etbc_tm  = param->pfp_mont_etb.etb_tm & 0x3;
	reg.pmc39_mont_reg.etbc_ptm = param->pfp_mont_etb.etb_ptm & 0x3;
	reg.pmc39_mont_reg.etbc_ppm = param->pfp_mont_etb.etb_ppm & 0x3;
	reg.pmc39_mont_reg.etbc_brt = param->pfp_mont_etb.etb_brt & 0x3;

	/*
	 * if DEAR-ALAT or DEAR-TLB is set then PMC12 must be set to zero (see documentation p. 87)
	 *
	 * D-EAR ALAT/TLB and ETB cannot be used at the same time.
	 * From documentation: PMC12 must be zero in this mode; else the wrong IP for misses
	 * coming right after a mispredicted branch.
	 *
	 * D-EAR cache is fine.
	 */
assign_zero:
	if (found_bad_dear && reg.pmc_val != 0UL) return PFMLIB_ERR_EVTINCOMP;

	if (pfm_regmask_isset(&inp->pfp_unavail_pmcs, 39))
		return PFMLIB_ERR_NOASSIGN;

	pc[pos1].reg_num     = 39;
	pc[pos1].reg_value   = reg.pmc_val;
	pc[pos1].reg_addr    = pc[pos1].reg_alt_addr = 39;
	pos1++;

	__pfm_vbprintf("[PMC39(pmc39)=0x%lx plm=%d pm=%d ds=%d tm=%d ptm=%d ppm=%d brt=%d]\n",
				reg.pmc_val,
				reg.pmc39_mont_reg.etbc_plm,
				reg.pmc39_mont_reg.etbc_pm,
				reg.pmc39_mont_reg.etbc_ds,
				reg.pmc39_mont_reg.etbc_tm,
				reg.pmc39_mont_reg.etbc_ptm,
				reg.pmc39_mont_reg.etbc_ppm,
				reg.pmc39_mont_reg.etbc_brt);

	/*
	 * only add ETB PMDs when actually using BTB.
	 * Not needed when dealing with D-EAR TLB and DEAR-ALAT
	 * PMC39 restriction
	 */
	if (found_etb || has_etb_param) {
		pd[pos2].reg_num = 38;
		pd[pos2].reg_addr = pd[pos2].reg_alt_addr = 38;
		pos2++;
		pd[pos2].reg_num = 39;
		pd[pos2].reg_addr = pd[pos2].reg_alt_addr  = 39;
		pos2++;
		__pfm_vbprintf("[PMD38(pmd38)]\n[PMD39(pmd39)\n");


		for(i=48; i < 64; i++, pos2++) {
			pd[pos2].reg_num = i;
			pd[pos2].reg_addr = pd[pos2].reg_alt_addr = i;
			__pfm_vbprintf("[PMD%u(pmd%u)]\n", pd[pos2].reg_num, pd[pos2].reg_num);
		}
	}

	/* update final number of entries used */
	outp->pfp_pmc_count = pos1;
	outp->pfp_pmd_count = pos2;

	return PFMLIB_SUCCESS;
}

static void
do_normal_rr(unsigned long start, unsigned long end,
	     pfmlib_reg_t *br, int nbr, int dir, int *idx, int *reg_idx, int plm)
{
	unsigned long size, l_addr, c;
	unsigned long l_offs = 0, r_offs = 0;
	unsigned long l_size, r_size;
	dbreg_t db;
	int p2;

	if (nbr < 1 || end <= start) return;

	size = end - start;

	DPRINT("start=0x%016lx end=0x%016lx size=0x%lx bytes (%lu bundles) nbr=%d dir=%d\n",
			start, end, size, size >> 4, nbr, dir);

	p2 = pfm_ia64_fls(size);

	c = ALIGN_DOWN(end, p2);

	DPRINT("largest power of two possible: 2^%d=0x%lx, crossing=0x%016lx\n",
				p2,
				1UL << p2, c);

	if ((c - (1UL<<p2)) >= start) {
		l_addr = c - (1UL << p2);
	} else {
		p2--;

		if ((c + (1UL<<p2)) <= end)  {
			l_addr = c;
		} else {
			l_addr = c - (1UL << p2);
		}
	}
	l_size = l_addr - start;
	r_size = end - l_addr-(1UL<<p2);

	if (PFMLIB_DEBUG()) {
		printf("largest chunk: 2^%d=0x%lx @0x%016lx-0x%016lx\n", p2, 1UL<<p2, l_addr, l_addr+(1UL<<p2));
		if (l_size) printf("before: 0x%016lx-0x%016lx\n", start, l_addr);
		if (r_size) printf("after : 0x%016lx-0x%016lx\n", l_addr+(1UL<<p2), end);
	}

	if (dir == 0 && l_size != 0 && nbr == 1) {
		p2++;
		l_addr = end - (1UL << p2);
		if (PFMLIB_DEBUG()) {
			l_offs = start - l_addr;
			printf(">>l_offs: 0x%lx\n", l_offs);
		}
	} else if (dir == 1 && r_size != 0 && nbr == 1) {
		p2++;
		l_addr = start;
		if (PFMLIB_DEBUG()) {
			r_offs = l_addr+(1UL<<p2) - end;
			printf(">>r_offs: 0x%lx\n", r_offs);
		}
	}
	l_size = l_addr - start;
	r_size = end - l_addr-(1UL<<p2);
	
	if (PFMLIB_DEBUG()) {
		printf(">>largest chunk: 2^%d @0x%016lx-0x%016lx\n", p2, l_addr, l_addr+(1UL<<p2));
		if (l_size && !l_offs) printf(">>before: 0x%016lx-0x%016lx\n", start, l_addr);
		if (r_size && !r_offs) printf(">>after : 0x%016lx-0x%016lx\n", l_addr+(1UL<<p2), end);
	}

	/*
	 * we initialize the mask to full 0 and
	 * only update the mask field. the rest is left
	 * to zero, except for the plm.
	 * in the case of ibr, the x-field must be 0. For dbr
	 * the value of r-field and w-field is ignored.
	 */

	db.val        = 0;
	db.db.db_mask = ~((1UL << p2)-1);
	/*
	 * we always use default privilege level.
	 * plm is ignored for DBRs.
	 */
	db.db.db_plm  = plm;


	br[*idx].reg_num    = *reg_idx;
	br[*idx].reg_value  = l_addr;
	br[*idx].reg_addr   = br[*idx].reg_alt_addr  = *reg_idx;

	br[*idx+1].reg_num   = *reg_idx+1;
	br[*idx+1].reg_value = db.val;
	br[*idx+1].reg_addr  = br[*idx+1].reg_alt_addr = *reg_idx+1;

	*idx     += 2;
	*reg_idx += 2;

	nbr--;
	if (nbr) {
		int r_nbr, l_nbr;

		r_nbr = l_nbr = nbr >>1;

		if (nbr & 0x1) {
			/*
			 * our simple heuristic is:
			 * we assign the largest number of registers to the largest
			 * of the two chunks
			 */
			if (l_size > r_size) {
				l_nbr++;
			} else {
				r_nbr++;
			}

		}
		do_normal_rr(start, l_addr, br, l_nbr, 0, idx, reg_idx, plm);
		do_normal_rr(l_addr+(1UL<<p2), end, br, r_nbr, 1, idx, reg_idx, plm);
	}
}

static void
print_one_range(pfmlib_mont_input_rr_desc_t *in_rr, pfmlib_mont_output_rr_desc_t *out_rr, pfmlib_reg_t *dbr, int base_idx, int n_pairs, int fine_mode, unsigned int rr_flags)
{
	int j;
	dbreg_t d;
	unsigned long r_end;

	__pfm_vbprintf("[0x%lx-0x%lx): %d register pair(s)%s%s\n",
			in_rr->rr_start, in_rr->rr_end,
			n_pairs,
			fine_mode ? ", fine_mode" : "",
			rr_flags & PFMLIB_MONT_RR_INV ? ", inversed" : "");

	__pfm_vbprintf("start offset: -0x%lx end_offset: +0x%lx\n", out_rr->rr_soff, out_rr->rr_eoff);

	for (j=0; j < n_pairs; j++, base_idx+=2) {

		d.val = dbr[base_idx+1].reg_value;
		r_end = dbr[base_idx].reg_value+((~(d.db.db_mask)) & ~(0xffUL << 56));

		if (fine_mode)
			__pfm_vbprintf("brp%u:  db%u: 0x%016lx db%u: plm=0x%x mask=0x%016lx\n",
						dbr[base_idx].reg_num>>1,
						dbr[base_idx].reg_num,
						dbr[base_idx].reg_value,
						dbr[base_idx+1].reg_num,
						d.db.db_plm, d.db.db_mask);
		else
			__pfm_vbprintf("brp%u:  db%u: 0x%016lx db%u: plm=0x%x mask=0x%016lx end=0x%016lx\n",
						dbr[base_idx].reg_num>>1,
						dbr[base_idx].reg_num,
						dbr[base_idx].reg_value,
						dbr[base_idx+1].reg_num,
						d.db.db_plm, d.db.db_mask,
						r_end);
	}
}

/*
 * base_idx = base register index to use (for IBRP1, base_idx = 2)
 */
static int
compute_fine_rr(pfmlib_mont_input_rr_t *irr, int dfl_plm, int n, int *base_idx, pfmlib_mont_output_rr_t *orr)
{
	int i;
	pfmlib_reg_t *br;
	pfmlib_mont_input_rr_desc_t *in_rr;
	pfmlib_mont_output_rr_desc_t *out_rr;
	unsigned long addr;
	int reg_idx;
	dbreg_t db;

	in_rr   = irr->rr_limits;
	out_rr  = orr->rr_infos;
	br      = orr->rr_br+orr->rr_nbr_used;
	reg_idx = *base_idx;

	db.val        = 0;
	db.db.db_mask = FINE_MODE_MASK;

	if (n > 2) return PFMLIB_ERR_IRRTOOMANY;

	for (i=0; i < n; i++, reg_idx += 2, in_rr++, br+= 4) {
		/*
		 * setup lower limit pair
		 *
		 * because of the PMU can only see addresses on a 2-bundle boundary, we must align 
		 * down to the closest bundle-pair aligned address. 5 => 32-byte aligned address
		 */
		addr            = ALIGN_DOWN(in_rr->rr_start, 5);
		out_rr->rr_soff = in_rr->rr_start - addr;

		/*
		 * adjust plm for each range
		 */
		db.db.db_plm    = in_rr->rr_plm ? in_rr->rr_plm : (unsigned long)dfl_plm;

		br[0].reg_num   = reg_idx;
		br[0].reg_value = addr;
		br[0].reg_addr  = br[0].reg_alt_addr = 1+reg_idx;
		br[1].reg_num   = reg_idx+1;
		br[1].reg_value = db.val;
		br[1].reg_addr  = br[1].reg_alt_addr = 1+reg_idx+1;

		/*
		 * setup upper limit pair
		 *
		 *
		 * In fine mode, the bundle address stored in the upper limit debug
		 * registers is included in the count, so we substract 0x10 to exclude it.
		 *
		 * because of the PMU bug, we align the (corrected) end to the nearest
		 * 32-byte aligned address + 0x10. With this correction and depending
		 * on the correction, we may count one
		 *
		 *
		 */
		
		addr = in_rr->rr_end - 0x10;

		if ((addr & 0x1f) == 0) addr += 0x10;
		out_rr->rr_eoff = addr - in_rr->rr_end + 0x10;

		br[2].reg_num   = reg_idx+4;
		br[2].reg_value = addr;
		br[2].reg_addr  = br[2].reg_alt_addr = 1+reg_idx+4;

		br[3].reg_num   = reg_idx+5;
		br[3].reg_value = db.val;
		br[3].reg_addr  = br[3].reg_alt_addr = 1+reg_idx+5;

		if (PFMLIB_VERBOSE()) print_one_range(in_rr, out_rr, br, 0, 2, 1, irr->rr_flags);
	}
	orr->rr_nbr_used += i<<2;

	/* update base_idx, for subsequent calls */
	*base_idx = reg_idx;

	return PFMLIB_SUCCESS;
}

/*
 * base_idx = base register index to use (for IBRP1, base_idx = 2)
 */
static int
compute_single_rr(pfmlib_mont_input_rr_t *irr, int dfl_plm, int *base_idx, pfmlib_mont_output_rr_t *orr)
{
	unsigned long size, end, start;
	unsigned long p_start, p_end;
	pfmlib_mont_input_rr_desc_t *in_rr;
	pfmlib_mont_output_rr_desc_t *out_rr;
	pfmlib_reg_t *br;
	dbreg_t db;
	int reg_idx;
	int l, m;

	in_rr   = irr->rr_limits;
	out_rr  = orr->rr_infos;
	br      = orr->rr_br+orr->rr_nbr_used;
	start   = in_rr->rr_start;
	end     = in_rr->rr_end;
	size    = end - start;
	reg_idx = *base_idx;

	l = pfm_ia64_fls(size);

	m = l;
	if (size & ((1UL << l)-1)) {
		if (l>62) {
			printf("range: [0x%lx-0x%lx] too big\n", start, end);
			return PFMLIB_ERR_IRRTOOBIG;
		}
		m++;
	}

	DPRINT("size=%ld, l=%d m=%d, internal: 0x%lx full: 0x%lx\n",
		size,
		l, m,
		1UL << l,
		1UL << m);

	for (; m < 64; m++) {
		p_start = ALIGN_DOWN(start, m);
		p_end   = p_start+(1UL<<m);
		if (p_end >= end) goto found;
	}
	return PFMLIB_ERR_IRRINVAL;
found:
	DPRINT("m=%d p_start=0x%lx p_end=0x%lx\n", m, p_start,p_end);

	/* when the event is not IA64_INST_RETIRED, then we MUST use ibrp0 */
	br[0].reg_num   = reg_idx;
	br[0].reg_value = p_start;
	br[0].reg_addr  = br[0].reg_alt_addr = 1+reg_idx;

	db.val        = 0;
	db.db.db_mask = ~((1UL << m)-1);
	db.db.db_plm  = in_rr->rr_plm ? in_rr->rr_plm : (unsigned long)dfl_plm;


	br[1].reg_num   = reg_idx + 1;
	br[1].reg_value = db.val;
	br[1].reg_addr  = br[1].reg_alt_addr = 1+reg_idx+1;

	out_rr->rr_soff = start - p_start;
	out_rr->rr_eoff = p_end - end;

	if (PFMLIB_VERBOSE()) print_one_range(in_rr, out_rr, br, 0, 1, 0, irr->rr_flags);

	orr->rr_nbr_used += 2;

	/* update base_idx, for subsequent calls */
	*base_idx = reg_idx;

	return PFMLIB_SUCCESS;
}

static int
compute_normal_rr(pfmlib_mont_input_rr_t *irr, int dfl_plm, int n, int *base_idx, pfmlib_mont_output_rr_t *orr)
{
	pfmlib_mont_input_rr_desc_t *in_rr;
	pfmlib_mont_output_rr_desc_t *out_rr;
	unsigned long r_end;
	pfmlib_reg_t *br;
	dbreg_t d;
	int i, j;
	int br_index, reg_idx, prev_index;

	in_rr    = irr->rr_limits;
	out_rr   = orr->rr_infos;
	br       = orr->rr_br+orr->rr_nbr_used;
	reg_idx  = *base_idx;
	br_index = 0;

	for (i=0; i < n; i++, in_rr++, out_rr++) {
		/*
		 * running out of registers
		 */
		if (br_index == 8) break;

		prev_index = br_index;

		do_normal_rr(	in_rr->rr_start,
				in_rr->rr_end,
				br,
				4 - (reg_idx>>1), /* how many pairs available */
				0,
				&br_index,
				&reg_idx, in_rr->rr_plm ? in_rr->rr_plm : dfl_plm);

		DPRINT("br_index=%d reg_idx=%d\n", br_index, reg_idx);

		/*
		 * compute offsets
		 */
		out_rr->rr_soff = out_rr->rr_eoff = 0;

		for(j=prev_index; j < br_index; j+=2) {

			d.val = br[j+1].reg_value;
			r_end = br[j].reg_value+((~(d.db.db_mask)+1) & ~(0xffUL << 56));

			if (br[j].reg_value <= in_rr->rr_start)
				out_rr->rr_soff = in_rr->rr_start - br[j].reg_value;

			if (r_end >= in_rr->rr_end)
				out_rr->rr_eoff = r_end - in_rr->rr_end;
		}

		if (PFMLIB_VERBOSE()) print_one_range(in_rr, out_rr, br, prev_index, (br_index-prev_index)>>1, 0, irr->rr_flags);
	}

	/* do not have enough registers to cover all the ranges */
	if (br_index == 8 && i < n) return PFMLIB_ERR_TOOMANY;

	orr->rr_nbr_used += br_index;

	/* update base_idx, for subsequent calls */
	*base_idx = reg_idx;

	return PFMLIB_SUCCESS;
}


static int
pfm_dispatch_irange(pfmlib_input_param_t *inp, pfmlib_mont_input_param_t *mod_in, pfmlib_output_param_t *outp, pfmlib_mont_output_param_t *mod_out)
{
	pfm_mont_pmc_reg_t reg;
	pfmlib_mont_input_param_t *param = mod_in;
	pfmlib_mont_input_rr_t *irr;
	pfmlib_mont_output_rr_t *orr;
	pfmlib_reg_t *pc = outp->pfp_pmcs;
	unsigned long retired_mask;
	unsigned int i, pos = outp->pfp_pmc_count, count;
	unsigned int retired_only, retired_count, fine_mode, prefetch_count;
	unsigned int n_intervals;
	int base_idx = 0, dup = 0;
	int ret;

	if (param == NULL) return PFMLIB_SUCCESS;

	if (param->pfp_mont_irange.rr_used == 0) return PFMLIB_SUCCESS;

	if (mod_out == NULL) return PFMLIB_ERR_INVAL;

	irr = &param->pfp_mont_irange;
	orr = &mod_out->pfp_mont_irange;

	ret = check_intervals(irr, 0, &n_intervals);
	if (ret != PFMLIB_SUCCESS) return ret;

	if (n_intervals < 1) return PFMLIB_ERR_IRRINVAL;
	

	retired_count  = check_inst_retired_events(inp, &retired_mask);
	retired_only   = retired_count == inp->pfp_event_count;
	fine_mode      = irr->rr_flags & PFMLIB_MONT_RR_NO_FINE_MODE ?
		         0 : check_fine_mode_possible(irr, n_intervals);


	DPRINT("n_intervals=%d retired_only=%d retired_count=%d fine_mode=%d\n",
		n_intervals, retired_only, retired_count, fine_mode);
	/*
	 * On montecito, there are more constraints on what can be measured with irange.
	 *
	 * - The fine mode is the best because you directly set the lower and upper limits of
	 *   the range. This uses 2 ibr pairs for range (ibrp0/ibrp2 and ibp1/ibrp3). Therefore
	 *   at most 2 fine mode ranges can be defined. The boundaries of the range must be in the
	 *   same 64KB page. The fine mode works will all events.
	 *
	 * - if the fine mode fails, then for all events, except IA64_TAGGED_INST_RETIRED_*, only
	 *   the first pair of ibr is available: ibrp0. This imposes some severe restrictions on the
	 *   size and alignment of the range. It can be bigger than 64KB and must be properly aligned
	 *   on its size. The library relaxes these constraints by allowing the covered areas to be
	 *   larger than the expected range. It may start before and end after the requested range. 
	 *   You can determine the amount of overrun in either direction for each range by looking at 
	 *   the rr_soff (start offset) and rr_eoff (end offset).
	 *
	 * - if the events include certain prefetch events then only IBRP1 can be used.
	 *   See 3.3.5.2 Exception 1.
	 *
	 * - Finally, when the events are ONLY IA64_TAGGED_INST_RETIRED_* then all IBR pairs can be used
	 *   to cover the range giving us more flexibility to approximate the range when it is not
	 *   properly aligned on its size (see 10.3.5.2 Exception 2). But the corresponding 
	 *   IA64_TAGGED_INST_RETIRED_* must be present.
	 */

	if (fine_mode == 0 && retired_only == 0 && n_intervals > 1) return PFMLIB_ERR_IRRTOOMANY;

	/* we do not default to non-fine mode to support more ranges */
	if (n_intervals > 2 && fine_mode == 1) return PFMLIB_ERR_IRRTOOMANY;

	ret = check_prefetch_events(inp, irr, &prefetch_count, &base_idx, &dup);
	if (ret)
		return ret;

	DPRINT("prefetch_count=%u base_idx=%d dup=%d\n", prefetch_count, base_idx, dup);

	/*
	 * CPU_OP_CYCLES.QUAL supports code range restrictions but it returns
	 * meaningful values (fine/coarse mode) only when IBRP1 is not used. 
	 */
	if ((base_idx > 0 || dup) && has_cpu_cycles_qual(inp))
		return PFMLIB_ERR_FEATCOMB;

	if (fine_mode == 0) {
		if (retired_only) {
			/* can take multiple intervals */
			ret = compute_normal_rr(irr, inp->pfp_dfl_plm, n_intervals, &base_idx, orr);
		} else {
			/* unless we have only prefetch and instruction retired events,
			 * we cannot satisfy the request because the other events cannot
			 * be measured on anything but IBRP0.
			 */
			if ((prefetch_count+retired_count) != inp->pfp_event_count)
				return PFMLIB_ERR_FEATCOMB;

			ret = compute_single_rr(irr, inp->pfp_dfl_plm, &base_idx, orr);
			if (ret == PFMLIB_SUCCESS && dup)
				ret = compute_single_rr(irr, inp->pfp_dfl_plm, &base_idx, orr);
		}
	} else {
		if (prefetch_count && n_intervals != 1) return PFMLIB_ERR_IRRTOOMANY;

		/* except is retired_only, can take only one interval */
		ret = compute_fine_rr(irr, inp->pfp_dfl_plm, n_intervals, &base_idx, orr);

		if (ret == PFMLIB_SUCCESS && dup)
			ret = compute_fine_rr(irr, inp->pfp_dfl_plm, n_intervals, &base_idx, orr);
	}

	if (ret != PFMLIB_SUCCESS)
		return ret == PFMLIB_ERR_TOOMANY ? PFMLIB_ERR_IRRTOOMANY : ret;

	reg.pmc_val = 0xdb6; /* default value */

	count = orr->rr_nbr_used;
	for (i=0; i < count; i++) {
		switch(orr->rr_br[i].reg_num) {
			case 0:
				reg.pmc38_mont_reg.iarc_ig_ibrp0 = 0;
				break;
			case 2:
				reg.pmc38_mont_reg.iarc_ig_ibrp1 = 0;
				break;
			case 4: 
				reg.pmc38_mont_reg.iarc_ig_ibrp2 = 0;
				break;
			case 6:
				reg.pmc38_mont_reg.iarc_ig_ibrp3 = 0;
				break;
		}
	}

	if (fine_mode) {
		reg.pmc38_mont_reg.iarc_fine = 1;
	} else if (retired_only) {
		/*
		 * we need to check that the user provided all the events needed to cover
		 * all the ibr pairs used to cover the range
		 */
		if ((retired_mask & 0x1) == 0 &&  reg.pmc38_mont_reg.iarc_ig_ibrp0 == 0) return PFMLIB_ERR_IRRINVAL;
		if ((retired_mask & 0x2) == 0 &&  reg.pmc38_mont_reg.iarc_ig_ibrp1 == 0) return PFMLIB_ERR_IRRINVAL;
		if ((retired_mask & 0x4) == 0 &&  reg.pmc38_mont_reg.iarc_ig_ibrp2 == 0) return PFMLIB_ERR_IRRINVAL;
		if ((retired_mask & 0x8) == 0 &&  reg.pmc38_mont_reg.iarc_ig_ibrp3 == 0) return PFMLIB_ERR_IRRINVAL;
	}

	if (pfm_regmask_isset(&inp->pfp_unavail_pmcs, 38))
		return PFMLIB_ERR_NOASSIGN;

	pc[pos].reg_num     = 38;
	pc[pos].reg_value   = reg.pmc_val;
	pc[pos].reg_addr    = pc[pos].reg_alt_addr = 38;
	pos++;

	__pfm_vbprintf("[PMC38(pmc38)=0x%lx ig_ibrp0=%d ig_ibrp1=%d ig_ibrp2=%d ig_ibrp3=%d fine=%d]\n",
			reg.pmc_val,
			reg.pmc38_mont_reg.iarc_ig_ibrp0,
			reg.pmc38_mont_reg.iarc_ig_ibrp1,
			reg.pmc38_mont_reg.iarc_ig_ibrp2,
			reg.pmc38_mont_reg.iarc_ig_ibrp3,
			reg.pmc38_mont_reg.iarc_fine);

	outp->pfp_pmc_count = pos;

	return PFMLIB_SUCCESS;
}

static const unsigned long iod_tab[8]={
	/* --- */	3,
	/* --D */	2,
	/* -O- */	3, /* should not be used */
	/* -OD */	0, /* =IOD safe because default IBR is harmless */
	/* I-- */	1, /* =IO safe because by defaut OPC is turned off */
	/* I-D */	0, /* =IOD safe because by default opc is turned off */
	/* IO- */	1,
	/* IOD */	0
};

/*
 * IMPORTANT: MUST BE CALLED *AFTER* pfm_dispatch_irange() to make sure we see
 * the irange programming to adjust pmc41.
 */
static int
pfm_dispatch_drange(pfmlib_input_param_t *inp, pfmlib_mont_input_param_t *mod_in, pfmlib_output_param_t *outp, pfmlib_mont_output_param_t *mod_out)
{
	pfmlib_mont_input_param_t *param = mod_in;
	pfmlib_reg_t *pc = outp->pfp_pmcs;
	pfmlib_mont_input_rr_t *irr;
	pfmlib_mont_output_rr_t *orr, *orr2;
	pfm_mont_pmc_reg_t pmc38;
	pfm_mont_pmc_reg_t reg;
	unsigned int i, pos = outp->pfp_pmc_count;
	int iod_codes[4], dfl_val_pmc32, dfl_val_pmc34;
	unsigned int n_intervals;
	int ret;
	int base_idx = 0;
	int fine_mode = 0;
#define DR_USED	0x1 /* data range is used */
#define OP_USED	0x2 /* opcode matching is used */
#define IR_USED	0x4 /* code range is used */

	if (param == NULL) return PFMLIB_SUCCESS;
	/*
	 * if only pmc32/pmc33 opcode matching is used, we do not need to change
	 * the default value of pmc41 regardless of the events being measured.
	 */
	if (  param->pfp_mont_drange.rr_used == 0
	   && param->pfp_mont_irange.rr_used == 0) return PFMLIB_SUCCESS;

	/*
	 * it seems like the ignored bits need to have special values
	 * otherwise this does not work.
	 */
	reg.pmc_val = 0x2078fefefefe;

	/*
	 * initialize iod codes
	 */
	iod_codes[0] = iod_codes[1] = iod_codes[2] = iod_codes[3] = 0;

	/*
	 * setup default iod value, we need to separate because
	 * if drange is used we do not know in advance which DBR will be used
	 * therefore we need to apply dfl_val later
	 */
	dfl_val_pmc32 = param->pfp_mont_opcm1.opcm_used ? OP_USED : 0;
	dfl_val_pmc34 = param->pfp_mont_opcm2.opcm_used ? OP_USED : 0;

	if (param->pfp_mont_drange.rr_used == 1) {

		if (mod_out == NULL) return PFMLIB_ERR_INVAL;

		irr = &param->pfp_mont_drange;
		orr = &mod_out->pfp_mont_drange;

		ret = check_intervals(irr, 1, &n_intervals);
		if (ret != PFMLIB_SUCCESS) return ret;

		if (n_intervals < 1) return PFMLIB_ERR_DRRINVAL;

		ret = compute_normal_rr(irr, inp->pfp_dfl_plm, n_intervals, &base_idx, orr);
		if (ret != PFMLIB_SUCCESS) {
			return ret == PFMLIB_ERR_TOOMANY ? PFMLIB_ERR_DRRTOOMANY : ret;
		}

		/*
		 * Update iod_codes to reflect the use of the DBR constraint.
		 */
		for (i=0; i < orr->rr_nbr_used; i++) {
			if (orr->rr_br[i].reg_num == 0) iod_codes[0] |= DR_USED | dfl_val_pmc32;
			if (orr->rr_br[i].reg_num == 2) iod_codes[1] |= DR_USED | dfl_val_pmc34;
			if (orr->rr_br[i].reg_num == 4) iod_codes[2] |= DR_USED | dfl_val_pmc32;
			if (orr->rr_br[i].reg_num == 6) iod_codes[3] |= DR_USED | dfl_val_pmc34;
		}

	}

	/*
	 * XXX: assume dispatch_irange executed before calling this function
	 */
	if (param->pfp_mont_irange.rr_used == 1) {

		orr2 = &mod_out->pfp_mont_irange;

		if (mod_out == NULL) return PFMLIB_ERR_INVAL;

		/*
		 * we need to find out whether or not the irange is using
		 * fine mode. If this is the case, then we only need to
		 * program pmc41 for the ibr pairs which designate the lower
		 * bounds of a range. For instance, if IBRP0/IBRP2 are used,
		 * then we only need to program pmc13.cfg_dbrp0 and pmc13.ena_dbrp0,
		 * the PMU will automatically use IBRP2, even though pmc13.ena_dbrp2=0.
		 */
		for(i=0; i <= pos; i++) {
			if (pc[i].reg_num == 38) {
				pmc38.pmc_val = pc[i].reg_value;
				if (pmc38.pmc38_mont_reg.iarc_fine == 1) fine_mode = 1;
				break;
			}
		}

		/*
		 * Update to reflect the use of the IBR constraint
		 */
		for (i=0; i < orr2->rr_nbr_used; i++) {
			if (orr2->rr_br[i].reg_num == 0) iod_codes[0] |= IR_USED | dfl_val_pmc32;
			if (orr2->rr_br[i].reg_num == 2) iod_codes[1] |= IR_USED | dfl_val_pmc34;
			if (fine_mode == 0 && orr2->rr_br[i].reg_num == 4) iod_codes[2] |= IR_USED | dfl_val_pmc32;
			if (fine_mode == 0 && orr2->rr_br[i].reg_num == 6) iod_codes[3] |= IR_USED | dfl_val_pmc34;
		}
	}

	if (param->pfp_mont_irange.rr_used == 0 && param->pfp_mont_drange.rr_used ==0) {
		iod_codes[0] = iod_codes[2] = dfl_val_pmc32;
		iod_codes[1] = iod_codes[3] = dfl_val_pmc34;
	}

	/*
	 * update the cfg dbrpX field. If we put a constraint on a cfg dbrp, then
	 * we must enable it in the corresponding ena_dbrpX
	 */
	reg.pmc41_mont_reg.darc_ena_dbrp0 = iod_codes[0] ? 1 : 0;
	reg.pmc41_mont_reg.darc_cfg_dtag0 = iod_tab[iod_codes[0]];

	reg.pmc41_mont_reg.darc_ena_dbrp1 = iod_codes[1] ? 1 : 0;
	reg.pmc41_mont_reg.darc_cfg_dtag1 = iod_tab[iod_codes[1]];

	reg.pmc41_mont_reg.darc_ena_dbrp2 = iod_codes[2] ? 1 : 0;
	reg.pmc41_mont_reg.darc_cfg_dtag2 = iod_tab[iod_codes[2]];

	reg.pmc41_mont_reg.darc_ena_dbrp3 = iod_codes[3] ? 1 : 0;
	reg.pmc41_mont_reg.darc_cfg_dtag3 = iod_tab[iod_codes[3]];

	if (pfm_regmask_isset(&inp->pfp_unavail_pmcs, 41))
		return PFMLIB_ERR_NOASSIGN;

	pc[pos].reg_num     = 41;
	pc[pos].reg_value   = reg.pmc_val;
	pc[pos].reg_addr    = pc[pos].reg_alt_addr = 41;
	pos++;

	__pfm_vbprintf("[PMC41(pmc41)=0x%lx cfg_dtag0=%d cfg_dtag1=%d cfg_dtag2=%d cfg_dtag3=%d ena_dbrp0=%d ena_dbrp1=%d ena_dbrp2=%d ena_dbrp3=%d]\n",
			reg.pmc_val,
			reg.pmc41_mont_reg.darc_cfg_dtag0,
			reg.pmc41_mont_reg.darc_cfg_dtag1,
			reg.pmc41_mont_reg.darc_cfg_dtag2,
			reg.pmc41_mont_reg.darc_cfg_dtag3,
			reg.pmc41_mont_reg.darc_ena_dbrp0,
			reg.pmc41_mont_reg.darc_ena_dbrp1,
			reg.pmc41_mont_reg.darc_ena_dbrp2,
			reg.pmc41_mont_reg.darc_ena_dbrp3);

	outp->pfp_pmc_count = pos;

	return PFMLIB_SUCCESS;
}

static int
check_qualifier_constraints(pfmlib_input_param_t *inp, pfmlib_mont_input_param_t *mod_in)
{
	pfmlib_mont_input_param_t *param = mod_in;
	pfmlib_event_t *e = inp->pfp_events;
	unsigned int i, count;
	

	count = inp->pfp_event_count;
	for(i=0; i < count; i++) {
		/*
		 * skip check for counter which requested it. Use at your own risk.
		 * No all counters have necessarily been validated for use with
		 * qualifiers. Typically the event is counted as if no constraint
		 * existed.
		 */
		if (param->pfp_mont_counters[i].flags & PFMLIB_MONT_FL_EVT_NO_QUALCHECK) continue;


		if (evt_use_irange(param) && has_iarr(e[i].event) == 0) return PFMLIB_ERR_FEATCOMB;
		if (evt_use_drange(param) && has_darr(e[i].event) == 0) return PFMLIB_ERR_FEATCOMB;
		if (evt_use_opcm(param) && has_opcm(e[i].event) == 0) return PFMLIB_ERR_FEATCOMB;
	}
	return PFMLIB_SUCCESS;
}

static int
check_range_plm(pfmlib_input_param_t *inp, pfmlib_mont_input_param_t *mod_in)
{
	pfmlib_mont_input_param_t *param = mod_in;
	unsigned int i, count;

	if (param->pfp_mont_drange.rr_used == 0 && param->pfp_mont_irange.rr_used == 0) return PFMLIB_SUCCESS;

	/*
	 * range restriction applies to all events, therefore we must have a consistent
	 * set of plm and they must match the pfp_dfl_plm which is used to setup the debug
	 * registers
	 */
	count = inp->pfp_event_count;
	for(i=0; i < count; i++) {
		if (inp->pfp_events[i].plm && inp->pfp_events[i].plm != inp->pfp_dfl_plm) return PFMLIB_ERR_FEATCOMB;
	}
	return PFMLIB_SUCCESS;
}

static int
pfm_dispatch_ipear(pfmlib_input_param_t *inp, pfmlib_mont_input_param_t *mod_in, pfmlib_output_param_t *outp)
{
	pfm_mont_pmc_reg_t reg;
	pfmlib_mont_input_param_t *param = mod_in;
	pfmlib_event_t *e = inp->pfp_events;
	pfmlib_reg_t *pc, *pd;
	unsigned int pos1, pos2;
	unsigned int i, count;

	pc = outp->pfp_pmcs;
	pd = outp->pfp_pmds;
	pos1 = outp->pfp_pmc_count;
	pos2 = outp->pfp_pmd_count;
	/*
	 * check if there is something to do
	 */
	if (param == NULL || param->pfp_mont_ipear.ipear_used == 0) return PFMLIB_SUCCESS;

	/*
	 * we need to look for use of ETB, because IP-EAR and ETB cannot be used at the
	 * same time
	 */
	if (param->pfp_mont_etb.etb_used) return PFMLIB_ERR_FEATCOMB;

	/*
	 * look for implicit ETB used because of BRANCH_EVENT
	 */
	count = inp->pfp_event_count;
	for (i=0; i < count; i++) {
		if (is_etb(e[i].event)) return PFMLIB_ERR_FEATCOMB;
	}
	reg.pmc_val = 0;

	reg.pmc42_mont_reg.ipear_plm   = param->pfp_mont_ipear.ipear_plm ? param->pfp_mont_ipear.ipear_plm : inp->pfp_dfl_plm;
	reg.pmc42_mont_reg.ipear_pm    = inp->pfp_flags & PFMLIB_PFP_SYSTEMWIDE ? 1 : 0;
	reg.pmc42_mont_reg.ipear_mode  = 4;
	reg.pmc42_mont_reg.ipear_delay = param->pfp_mont_ipear.ipear_delay;

	if (pfm_regmask_isset(&inp->pfp_unavail_pmcs, 42))
		return PFMLIB_ERR_NOASSIGN;

	pc[pos1].reg_num     = 42;
	pc[pos1].reg_value   = reg.pmc_val;
	pc[pos1].reg_addr    = pc[pos1].reg_alt_addr = 42;
	pos1++;

	__pfm_vbprintf("[PMC42(pmc42)=0x%lx plm=%d pm=%d mode=%d delay=%d]\n",
			reg.pmc_val,
			reg.pmc42_mont_reg.ipear_plm,
			reg.pmc42_mont_reg.ipear_pm,
			reg.pmc42_mont_reg.ipear_mode,
			reg.pmc42_mont_reg.ipear_delay);

	pd[pos2].reg_num = 38;
	pd[pos2].reg_addr = pd[pos2].reg_alt_addr = 38;
	pos2++;
	pd[pos2].reg_num = 39;
	pd[pos2].reg_addr = pd[pos2].reg_alt_addr = 39;
	pos2++;
	__pfm_vbprintf("[PMD38(pmd38)]\n[PMD39(pmd39)\n");

	for(i=48; i < 64; i++, pos2++) {
		pd[pos2].reg_num = i;
		pd[pos2].reg_addr = pd[pos2].reg_alt_addr = i;
		__pfm_vbprintf("[PMD%u(pmd%u)]\n", pd[pos2].reg_num, pd[pos2].reg_num);
	}

	outp->pfp_pmc_count = pos1;
	outp->pfp_pmd_count = pos2;

	return PFMLIB_SUCCESS;
}

static int
pfm_mont_dispatch_events(pfmlib_input_param_t *inp, void *model_in, pfmlib_output_param_t *outp, void *model_out)
{
	int ret;
	pfmlib_mont_input_param_t *mod_in  = (pfmlib_mont_input_param_t *)model_in;
	pfmlib_mont_output_param_t *mod_out = (pfmlib_mont_output_param_t *)model_out;

	/*
	 * nothing will come out of this combination
	 */
	if (mod_out && mod_in == NULL) return PFMLIB_ERR_INVAL;

	/* check opcode match, range restriction qualifiers */
	if (mod_in && check_qualifier_constraints(inp, mod_in) != PFMLIB_SUCCESS) return PFMLIB_ERR_FEATCOMB;

	/* check for problems with range restriction and per-event plm */
	if (mod_in && check_range_plm(inp, mod_in) != PFMLIB_SUCCESS) return PFMLIB_ERR_FEATCOMB;

	ret = pfm_mont_dispatch_counters(inp, mod_in, outp);
	if (ret != PFMLIB_SUCCESS) return ret;

	/* now check for I-EAR */
	ret = pfm_dispatch_iear(inp, mod_in, outp);
	if (ret != PFMLIB_SUCCESS) return ret;

	/* now check for D-EAR */
	ret = pfm_dispatch_dear(inp, mod_in, outp);
	if (ret != PFMLIB_SUCCESS) return ret;

	/* XXX: must be done before dispatch_opcm()  and dispatch_drange() */
	ret = pfm_dispatch_irange(inp, mod_in, outp, mod_out);;
	if (ret != PFMLIB_SUCCESS) return ret;

	ret = pfm_dispatch_drange(inp, mod_in, outp, mod_out);;
	if (ret != PFMLIB_SUCCESS) return ret;

	/* now check for Opcode matchers */
	ret = pfm_dispatch_opcm(inp, mod_in, outp, mod_out);
	if (ret != PFMLIB_SUCCESS) return ret;

	/* now check for ETB */
	ret = pfm_dispatch_etb(inp, mod_in, outp);
	if (ret != PFMLIB_SUCCESS) return ret;

	/* now check for IP-EAR */
	ret = pfm_dispatch_ipear(inp, mod_in, outp);

	return ret;
}


/* XXX: return value is also error code */
int
pfm_mont_get_event_maxincr(unsigned int i, unsigned int *maxincr)
{
	if (i >= PME_MONT_EVENT_COUNT || maxincr == NULL) return PFMLIB_ERR_INVAL;
	*maxincr = montecito_pe[i].pme_maxincr;
	return PFMLIB_SUCCESS;
}

int
pfm_mont_is_ear(unsigned int i)
{
	return i < PME_MONT_EVENT_COUNT && is_ear(i);
}

int
pfm_mont_is_dear(unsigned int i)
{
	return i < PME_MONT_EVENT_COUNT && is_dear(i);
}

int
pfm_mont_is_dear_tlb(unsigned int i)
{
	return i < PME_MONT_EVENT_COUNT && is_dear(i) && is_ear_tlb(i);
}
	
int
pfm_mont_is_dear_cache(unsigned int i)
{
	return i < PME_MONT_EVENT_COUNT && is_dear(i) && is_ear_cache(i);
}

int
pfm_mont_is_dear_alat(unsigned int i)
{
	return i < PME_MONT_EVENT_COUNT && is_ear_alat(i);
}
	
int
pfm_mont_is_iear(unsigned int i)
{
	return i < PME_MONT_EVENT_COUNT && is_iear(i);
}

int
pfm_mont_is_iear_tlb(unsigned int i)
{
	return i < PME_MONT_EVENT_COUNT && is_iear(i) && is_ear_tlb(i);
}
	
int
pfm_mont_is_iear_cache(unsigned int i)
{
	return i < PME_MONT_EVENT_COUNT && is_iear(i) && is_ear_cache(i);
}
	
int
pfm_mont_is_etb(unsigned int i)
{
	return i < PME_MONT_EVENT_COUNT && is_etb(i);
}

int
pfm_mont_support_iarr(unsigned int i)
{
	return i < PME_MONT_EVENT_COUNT && has_iarr(i);
}


int
pfm_mont_support_darr(unsigned int i)
{
	return i < PME_MONT_EVENT_COUNT  && has_darr(i);
}


int
pfm_mont_support_opcm(unsigned int i)
{
	return i < PME_MONT_EVENT_COUNT && has_opcm(i);
}

int
pfm_mont_support_all(unsigned int i)
{
	return i < PME_MONT_EVENT_COUNT && has_all(i);
}


int
pfm_mont_get_ear_mode(unsigned int i, pfmlib_mont_ear_mode_t *m)
{
	pfmlib_mont_ear_mode_t r;

	if (!is_ear(i) || m == NULL) return PFMLIB_ERR_INVAL;

	r = PFMLIB_MONT_EAR_TLB_MODE;
	if (is_ear_tlb(i))  goto done;

	r = PFMLIB_MONT_EAR_CACHE_MODE;
	if (is_ear_cache(i))  goto done;

	r = PFMLIB_MONT_EAR_ALAT_MODE;
	if (is_ear_alat(i)) goto done;

	return PFMLIB_ERR_INVAL;
done:
	*m = r;
	return PFMLIB_SUCCESS;
}

static int
pfm_mont_get_event_code(unsigned int i, unsigned int cnt, int *code)
{
	if (cnt != PFMLIB_CNT_FIRST && (cnt < 4 || cnt > 15))
		return PFMLIB_ERR_INVAL;

	*code = (int)montecito_pe[i].pme_code;

	return PFMLIB_SUCCESS;
}

/*
 * This function is accessible directly to the user
 */
int
pfm_mont_get_event_umask(unsigned int i, unsigned long *umask)
{
	if (i >= PME_MONT_EVENT_COUNT || umask == NULL) return PFMLIB_ERR_INVAL;
	*umask = evt_umask(i);
	return PFMLIB_SUCCESS;
}
	
int
pfm_mont_get_event_group(unsigned int i, int *grp)
{
	if (i >= PME_MONT_EVENT_COUNT || grp == NULL) return PFMLIB_ERR_INVAL;
	*grp = evt_grp(i);
	return PFMLIB_SUCCESS;
}

int
pfm_mont_get_event_set(unsigned int i, int *set)
{
	if (i >= PME_MONT_EVENT_COUNT || set == NULL) return PFMLIB_ERR_INVAL;
	*set = evt_set(i) == 0xf ? PFMLIB_MONT_EVT_NO_SET : evt_set(i);
	return PFMLIB_SUCCESS;
}

int
pfm_mont_get_event_type(unsigned int i, int *type)
{
	if (i >= PME_MONT_EVENT_COUNT || type == NULL) return PFMLIB_ERR_INVAL;
	*type = evt_caf(i);
	return PFMLIB_SUCCESS;
}

/* external interface */
int
pfm_mont_irange_is_fine(pfmlib_output_param_t *outp, pfmlib_mont_output_param_t *mod_out)
{
	pfmlib_mont_output_param_t *param = mod_out;
	pfm_mont_pmc_reg_t reg;
	unsigned int i, count;

	/* some sanity checks */
	if (outp == NULL || param == NULL) return 0;
	if (outp->pfp_pmc_count >= PFMLIB_MAX_PMCS) return 0;

	if (param->pfp_mont_irange.rr_nbr_used == 0) return 0;

	/*
	 * we look for pmc38 as it contains the bit indicating if fine mode is used
	 */
	count = outp->pfp_pmc_count;
	for(i=0; i < count; i++) {
		if (outp->pfp_pmcs[i].reg_num == 38) goto found;
	}
	return 0;
found:
	reg.pmc_val = outp->pfp_pmcs[i].reg_value;
	return reg.pmc38_mont_reg.iarc_fine ? 1 : 0;
}

static char *
pfm_mont_get_event_name(unsigned int i)
{
	return montecito_pe[i].pme_name;
}

static void
pfm_mont_get_event_counters(unsigned int j, pfmlib_regmask_t *counters)
{
	unsigned int i;
	unsigned long m;

	memset(counters, 0, sizeof(*counters));

	m =montecito_pe[j].pme_counters;
	for(i=0; m ; i++, m>>=1) {
		if (m & 0x1)
			pfm_regmask_set(counters, i);
	}
}

static void
pfm_mont_get_impl_pmcs(pfmlib_regmask_t *impl_pmcs)
{
	unsigned int i = 0;

	for(i=0; i < 16; i++)
		pfm_regmask_set(impl_pmcs, i);

	for(i=32; i < 43; i++)
		pfm_regmask_set(impl_pmcs, i);
}

static void
pfm_mont_get_impl_pmds(pfmlib_regmask_t *impl_pmds)
{
	unsigned int i = 0;

	for(i=4; i < 16; i++)
		pfm_regmask_set(impl_pmds, i);
	for(i=32; i < 40; i++)
		pfm_regmask_set(impl_pmds, i);
	for(i=48; i < 64; i++)
		pfm_regmask_set(impl_pmds, i);
}

static void
pfm_mont_get_impl_counters(pfmlib_regmask_t *impl_counters)
{
	unsigned int i = 0;

	/* counter pmds are contiguous */
	for(i=4; i < 16; i++)
		pfm_regmask_set(impl_counters, i);
}

static void
pfm_mont_get_hw_counter_width(unsigned int *width)
{
	*width = PMU_MONT_COUNTER_WIDTH;
}

static int
pfm_mont_get_event_description(unsigned int ev, char **str)
{
	char *s;
	s = montecito_pe[ev].pme_desc;
	if (s) {
		*str = strdup(s);
	} else {
		*str = NULL;
	}
	return PFMLIB_SUCCESS;
}

static int
pfm_mont_get_cycle_event(pfmlib_event_t *e)
{
	e->event = PME_MONT_CPU_OP_CYCLES_ALL;
	return PFMLIB_SUCCESS;

}

static int
pfm_mont_get_inst_retired(pfmlib_event_t *e)
{
	e->event = PME_MONT_IA64_INST_RETIRED;
	return PFMLIB_SUCCESS;
}

static unsigned int
pfm_mont_get_num_event_masks(unsigned int event)
{
	return has_mesi(event) ? 4 : 0;
}

static char *
pfm_mont_get_event_mask_name(unsigned int event, unsigned int mask)
{
	switch(mask) {
		case 0: return "I";
		case 1: return "S";
		case 2: return "E";
		case 3: return "M";	
	}
	return NULL;
}

static int
pfm_mont_get_event_mask_desc(unsigned int event, unsigned int mask, char **desc)
{
	switch(mask) {
		case 0: *desc = strdup("invalid");
			break;
		case 1: *desc = strdup("shared");
			break;
		case 2: *desc = strdup("exclusive");
			break;
		case 3: *desc = strdup("modified");	
			break;
		default:
			return PFMLIB_ERR_INVAL;
	}
	return PFMLIB_SUCCESS;
}

static int
pfm_mont_get_event_mask_code(unsigned int event,
		 	     unsigned int mask, unsigned int *code)
{
	*code = mask;
	return PFMLIB_SUCCESS;
}

pfm_pmu_support_t montecito_support={
	.pmu_name		= "dual-core Itanium 2",
	.pmu_type		= PFMLIB_MONTECITO_PMU,
	.pme_count		= PME_MONT_EVENT_COUNT,
	.pmc_count		= PMU_MONT_NUM_PMCS,
	.pmd_count		= PMU_MONT_NUM_PMDS,
	.num_cnt		= PMU_MONT_NUM_COUNTERS,
	.get_event_code		= pfm_mont_get_event_code,
	.get_event_name		= pfm_mont_get_event_name,
	.get_event_counters	= pfm_mont_get_event_counters,
	.dispatch_events	= pfm_mont_dispatch_events,
	.pmu_detect		= pfm_mont_detect,
	.get_impl_pmcs		= pfm_mont_get_impl_pmcs,
	.get_impl_pmds		= pfm_mont_get_impl_pmds,
	.get_impl_counters	= pfm_mont_get_impl_counters,
	.get_hw_counter_width	= pfm_mont_get_hw_counter_width,
	.get_event_desc         = pfm_mont_get_event_description,
	.get_cycle_event	= pfm_mont_get_cycle_event,
	.get_inst_retired_event = pfm_mont_get_inst_retired,
	.get_num_event_masks	= pfm_mont_get_num_event_masks,
	.get_event_mask_name	= pfm_mont_get_event_mask_name,
	.get_event_mask_desc	= pfm_mont_get_event_mask_desc,
	.get_event_mask_code	= pfm_mont_get_event_mask_code
};
