/*
 * pfmlib_itanium2.c : support for the Itanium2 PMU family
 *
 * Copyright (c) 2002-2006 Hewlett-Packard Development Company, L.P.
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

/* public headers */
#include <perfmon/pfmlib_itanium2.h>

/* private headers */
#include "pfmlib_priv.h"		/* library private */
#include "pfmlib_priv_ia64.h"		/* architecture private */
#include "pfmlib_itanium2_priv.h"	/* PMU private */
#include "itanium2_events.h"		/* PMU private */

#define is_ear(i)	event_is_ear(itanium2_pe+(i))
#define is_ear_tlb(i)	event_is_ear_tlb(itanium2_pe+(i))
#define is_ear_alat(i)	event_is_ear_alat(itanium2_pe+(i))
#define is_ear_cache(i)	event_is_ear_cache(itanium2_pe+(i))
#define is_iear(i)	event_is_iear(itanium2_pe+(i))
#define is_dear(i)	event_is_dear(itanium2_pe+(i))
#define is_btb(i)	event_is_btb(itanium2_pe+(i))
#define has_opcm(i)	event_opcm_ok(itanium2_pe+(i))
#define has_iarr(i)	event_iarr_ok(itanium2_pe+(i))
#define has_darr(i)	event_darr_ok(itanium2_pe+(i))

#define evt_use_opcm(e)		((e)->pfp_ita2_pmc8.opcm_used != 0 || (e)->pfp_ita2_pmc9.opcm_used !=0)
#define evt_use_irange(e)	((e)->pfp_ita2_irange.rr_used)
#define evt_use_drange(e)	((e)->pfp_ita2_drange.rr_used)

#define evt_grp(e)	(int)itanium2_pe[e].pme_qualifiers.pme_qual.pme_group
#define evt_set(e)	(int)itanium2_pe[e].pme_qualifiers.pme_qual.pme_set
#define evt_umask(e)	itanium2_pe[e].pme_umask


#define FINE_MODE_BOUNDARY_BITS	12
#define FINE_MODE_MASK		~((1U<<12)-1)

/* let's define some handy shortcuts! */
#define pmc_plm		pmc_ita2_counter_reg.pmc_plm
#define pmc_ev		pmc_ita2_counter_reg.pmc_ev
#define pmc_oi		pmc_ita2_counter_reg.pmc_oi
#define pmc_pm		pmc_ita2_counter_reg.pmc_pm
#define pmc_es		pmc_ita2_counter_reg.pmc_es
#define pmc_umask	pmc_ita2_counter_reg.pmc_umask
#define pmc_thres	pmc_ita2_counter_reg.pmc_thres
#define pmc_ism		pmc_ita2_counter_reg.pmc_ism

static char * pfm_ita2_get_event_name(unsigned int i);

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

/*
 * The Itanium2 PMU has a bug in the fine mode implementation.
 * It only sees ranges with a granularity of two bundles.
 * So we prepare for the day they fix it.
 */
static int has_fine_mode_bug;

static int
pfm_ita2_detect(void)
{
	int tmp;
	int ret = PFMLIB_ERR_NOTSUPP;

	tmp = pfm_ia64_get_cpu_family();
	if (tmp == 0x1f) {
		has_fine_mode_bug = 1;
		ret = PFMLIB_SUCCESS;
	}
	return ret;
}

/*
 * Check the event for incompatibilities. This is useful
 * for L1 and L2 related events. Due to wire limitations,
 * some caches events are separated into sets. There
 * are 5 sets for the L1D cache group and 6 sets for L2 group.
 * It is NOT possible to simultaneously measure events from
 * differents sets within a group. For instance, you cannot
 * measure events from set0 and set1 in L1D cache group. However
 * it is possible to measure set0 in L1D and set1 in L2 at the same
 * time.
 *
 * This function verifies that the set constraint are respected.
 */
static int
check_cross_groups_and_umasks(pfmlib_input_param_t *inp)
{
	unsigned long ref_umask, umask;
	int g, s;
	unsigned int cnt = inp->pfp_event_count;
	pfmlib_event_t *e = inp->pfp_events;
	unsigned int i, j;

	/*
	 * XXX: could possibly be optimized
	 */
	for (i=0; i < cnt; i++) {
		g = evt_grp(e[i].event);
		s = evt_set(e[i].event);

		if (g == PFMLIB_ITA2_EVT_NO_GRP) continue;

		ref_umask = evt_umask(e[i].event);

		for (j=i+1; j < cnt; j++) {
			if (evt_grp(e[j].event) != g) continue;
			if (evt_set(e[j].event) != s) return PFMLIB_ERR_EVTSET;
			
			/* only care about L2 cache group */
			if (g != PFMLIB_ITA2_EVT_L2_CACHE_GRP || (s == 1 || s == 2)) continue;

			umask = evt_umask(e[j].event);
			/*
			 * there is no assignement possible if the event in PMC4
			 * has a umask (ref_umask) and an event (from the same
			 * set) also has a umask AND it is different. For some
			 * sets, the umasks are shared, therefore the value
			 * programmed into PMC4 determines the umask for all
			 * the other events (with umask) from the set.
			 */
			if (umask && ref_umask != umask) return PFMLIB_ERR_NOASSIGN;
		}
	}
	return PFMLIB_SUCCESS;
}

/*
 * Certain prefetch events must be treated specially when instruction range restriction
 * is in use because they can only be constrained by IBRP1 in fine-mode. Other events
 * will use IBRP0 if tagged as a demand fetch OR IBPR1 if tagged as a prefetch match.
 * From the library's point of view there is no way of distinguishing this, so we leave
 * it up to the user to interpret the results.
 *
 * Events which can be qualified by the two pairs depending on their tag:
 * 	- IBP_BUNPAIRS_IN
 * 	- L1I_FETCH_RAB_HIT
 *	- L1I_FETCH_ISB_HIT
 * 	- L1I_FILLS
 *
 * This function returns the number of qualifying prefetch events found
 *
 * XXX: not clear which events do qualify as prefetch events.
 */
static int prefetch_events[]={
	PME_ITA2_L1I_PREFETCHES,
	PME_ITA2_L1I_STRM_PREFETCHES,
	PME_ITA2_L2_INST_PREFETCHES
};
#define NPREFETCH_EVENTS	sizeof(prefetch_events)/sizeof(int)

static int
check_prefetch_events(pfmlib_input_param_t *inp)
{
	int code;
	int prefetch_codes[NPREFETCH_EVENTS];
	unsigned int i, j, count;
	int c;
	int found = 0;

	for(i=0; i < NPREFETCH_EVENTS; i++) {
		pfm_get_event_code(prefetch_events[i], &code);
		prefetch_codes[i] = code;
	}
	count = inp->pfp_event_count;
	for(i=0; i < count; i++) {
		pfm_get_event_code(inp->pfp_events[i].event, &c);
		for(j=0; j < NPREFETCH_EVENTS; j++) {
			if (c == prefetch_codes[j]) found++;
		}
	}
	return found;
}


/*
 * IA64_INST_RETIRED (and subevents) is the only event which can be measured on all
 * 4 IBR when non-fine mode is not possible.
 *
 * This function returns:
 * 	- the number of events matching the IA64_INST_RETIRED code
 * 	- in retired_mask the bottom 4 bits indicates which of the 4 INST_RETIRED event
 * 	is present
 */
static unsigned int
check_inst_retired_events(pfmlib_input_param_t *inp, unsigned long *retired_mask)
{
	int code;
	int c;
	unsigned int i, count, found = 0;
	unsigned long umask, mask;

	pfm_get_event_code(PME_ITA2_IA64_INST_RETIRED_THIS, &code);

	count = inp->pfp_event_count;
	mask  = 0;
	for(i=0; i < count; i++) {
		pfm_get_event_code(inp->pfp_events[i].event, &c);
		if (c == code)  {
			pfm_ita2_get_event_umask(inp->pfp_events[i].event, &umask);
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
check_fine_mode_possible(pfmlib_ita2_input_rr_t *rr, int n)
{
	pfmlib_ita2_input_rr_desc_t *lim = rr->rr_limits;
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
check_intervals(pfmlib_ita2_input_rr_t *irr, int mode, unsigned int *n_intervals)
{
	unsigned int i;
	pfmlib_ita2_input_rr_desc_t *lim = irr->rr_limits;

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


static int
valid_assign(pfmlib_event_t *e, unsigned int *as, pfmlib_regmask_t *r_pmcs, unsigned int cnt)
{
	unsigned long pmc4_umask = 0, umask;
	char *name;
	int l1_grp_present = 0, l2_grp_present = 0;
	unsigned int i;
	int c, failure;
	int need_pmc5, need_pmc4;
  	int pmc5_evt = -1, pmc4_evt = -1;

	if (PFMLIB_DEBUG()) {
		unsigned int j;
		for(j=0;j<cnt; j++) {
			name = pfm_ita2_get_event_name(e[j].event);
			printf("%-2u (%d,%d): %s\n",
				as[j],
				evt_grp(e[j].event) == PFMLIB_ITA2_EVT_NO_GRP ? -1 : evt_grp(e[j].event),
				evt_set(e[j].event) == 0xf ? -1 : evt_set(e[j].event),
				name);

		}
	}
	failure = 1;
	/*
	 * first: check that all events have an assigned counter
	 */
	for(i=0; i < cnt; i++) {
		if (as[i]==0) goto do_failure;
		/*
		 * take care of restricted PMC registers
		 */
		if (pfm_regmask_isset(r_pmcs, as[i]))
			goto do_failure;
	}

	/*
	 * second: scan list of events for the presence of groups
	 * at this point, we know that there can be no set crossing per group
	 * because this has been tested earlier.
	 */
	for(i=0; i < cnt; i++) {

		c = e[i].event;

		if (evt_grp(c) == PFMLIB_ITA2_EVT_L1_CACHE_GRP) l1_grp_present = 1;

		if (evt_grp(c) == PFMLIB_ITA2_EVT_L2_CACHE_GRP) l2_grp_present = 1;
	}

	/*
	 * third: scan assignements and make sure that there is at least one
	 * member of a special group assigned to either PMC4 or PMC5 depending
	 * on the constraint for that group
	 */
	if (l1_grp_present || l2_grp_present) {

		need_pmc5 = l1_grp_present;
		need_pmc4 = l2_grp_present;

		for(i=0; i < cnt; i++) {

			if (need_pmc5 && as[i] == 5 && evt_grp(e[i].event) == PFMLIB_ITA2_EVT_L1_CACHE_GRP) {
				need_pmc5 = 0;
				pmc5_evt = e[i].event;
			}

			if (need_pmc4 && as[i] == 4 && evt_grp(e[i].event) == PFMLIB_ITA2_EVT_L2_CACHE_GRP) {
				need_pmc4 = 0;
				pmc4_evt = e[i].event;
			}

			if (need_pmc4 == 0 && need_pmc5 == 0) break;
		}
		failure = 2;
		if (need_pmc4) goto do_failure;

		failure = 3;
		if (need_pmc5) goto do_failure;
	}
	/*
	 * fourth: for the L2 cache event group, you must make sure that there is no
	 * umask conflict, except for sets 1 and 2 which do not suffer from this restriction.
	 * The umask in PMC4 determines the umask for all the other events in the same set.
	 * It is ignored if the event does no belong to a set or if the event has no
	 * umask (don't care umask).
	 *
	 * XXX: redudant, already checked in check_cross_groups_and_umasks(pfmlib_param_t *evt)
	 */
	if (l2_grp_present && evt_set(pmc4_evt) != 1 && evt_set(pmc4_evt) != 2) {

		/*
		 * extract the umask of the "key" event
		 */
		pmc4_umask = evt_umask(pmc4_evt);

		failure = 4;

		for(i=0; i < cnt; i++) {

			umask = evt_umask(e[i].event);

			DPRINT("pmc4_evt=%d pmc4_umask=0x%lx cnt_list[%d]=%d grp=%d umask=0x%lx\n", pmc4_evt, pmc4_umask, i, e[i].event,evt_grp(e[i].event), umask);

			if (as[i] != 4 && evt_grp(e[i].event) == PFMLIB_ITA2_EVT_L2_CACHE_GRP && umask != 0 && umask != pmc4_umask) break;
		}
		if (i != cnt) goto do_failure;
	}

	return PFMLIB_SUCCESS;
do_failure:
	DPRINT("%s : failure %d\n", __FUNCTION__, failure);
	return PFMLIB_ERR_NOASSIGN;
}

/*
 * It is not possible to measure more than one of the
 * L2_OZQ_CANCELS0, L2_OZQ_CANCELS1, L2_OZQ_CANCELS2 at the
 * same time.
 */

static int cancel_events[]=
{
	PME_ITA2_L2_OZQ_CANCELS0_ANY,
	PME_ITA2_L2_OZQ_CANCELS1_REL,
	PME_ITA2_L2_OZQ_CANCELS2_ACQ
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
 * Upon return the pfarg_regt structure is ready to be submitted to kernel
 */
static int
pfm_ita2_dispatch_counters(pfmlib_input_param_t *inp, pfmlib_ita2_input_param_t *mod_in, pfmlib_output_param_t *outp)
{
#define	has_counter(e,b)	(itanium2_pe[e].pme_counters & (1 << (b)) ? (b) : 0)
	pfmlib_ita2_input_param_t *param = mod_in;
	pfm_ita2_pmc_reg_t reg;
	pfmlib_event_t *e;
	pfmlib_reg_t *pc, *pd;
	pfmlib_regmask_t *r_pmcs;
	unsigned int i,j,k,l;
	int ret;
	unsigned int max_l0, max_l1, max_l2, max_l3;
	unsigned int assign[PMU_ITA2_NUM_COUNTERS];
	unsigned int m, cnt;

	e      = inp->pfp_events;
	pc     = outp->pfp_pmcs;
	pd     = outp->pfp_pmds;
	cnt    = inp->pfp_event_count;
	r_pmcs = &inp->pfp_unavail_pmcs;

	if (PFMLIB_DEBUG())
		for (m=0; m < cnt; m++) {
			DPRINT("ev[%d]=%s counters=0x%lx\n", m, itanium2_pe[e[m].event].pme_name,
				itanium2_pe[e[m].event].pme_counters);
		}

	if (cnt > PMU_ITA2_NUM_COUNTERS) return PFMLIB_ERR_TOOMANY;

	ret = check_cross_groups_and_umasks(inp);
	if (ret != PFMLIB_SUCCESS) return ret;

	ret = check_cancel_events(inp);
	if (ret != PFMLIB_SUCCESS) return ret;

	max_l0 = PMU_ITA2_FIRST_COUNTER + PMU_ITA2_NUM_COUNTERS;
	max_l1 = PMU_ITA2_FIRST_COUNTER + PMU_ITA2_NUM_COUNTERS*(cnt>1);
	max_l2 = PMU_ITA2_FIRST_COUNTER + PMU_ITA2_NUM_COUNTERS*(cnt>2);
	max_l3 = PMU_ITA2_FIRST_COUNTER + PMU_ITA2_NUM_COUNTERS*(cnt>3);

	DPRINT("max_l0=%u max_l1=%u max_l2=%u max_l3=%u\n", max_l0, max_l1, max_l2, max_l3);
	/*
	 *  For now, worst case in the loop nest: 4! (factorial)
	 */
	for (i=PMU_ITA2_FIRST_COUNTER; i < max_l0; i++) {

		assign[0] = has_counter(e[0].event,i);

		if (max_l1 == PMU_ITA2_FIRST_COUNTER && valid_assign(e, assign, r_pmcs, cnt) == PFMLIB_SUCCESS) goto done;

		for (j=PMU_ITA2_FIRST_COUNTER; j < max_l1; j++) {

			if (j == i) continue;

			assign[1] = has_counter(e[1].event,j);

			if (max_l2 == PMU_ITA2_FIRST_COUNTER && valid_assign(e, assign, r_pmcs, cnt) == PFMLIB_SUCCESS) goto done;

			for (k=PMU_ITA2_FIRST_COUNTER; k < max_l2; k++) {

				if(k == i || k == j) continue;

				assign[2] = has_counter(e[2].event,k);

				if (max_l3 == PMU_ITA2_FIRST_COUNTER && valid_assign(e, assign, r_pmcs, cnt) == PFMLIB_SUCCESS) goto done;
				for (l=PMU_ITA2_FIRST_COUNTER; l < max_l3; l++) {

					if(l == i || l == j || l == k) continue;

					assign[3] = has_counter(e[3].event,l);

					if (valid_assign(e, assign, r_pmcs, cnt) == PFMLIB_SUCCESS) goto done;
				}
			}
		}
	}
	/* we cannot satisfy the constraints */
	return PFMLIB_ERR_NOASSIGN;
done:
	for (j=0; j < cnt ; j++ ) {
		reg.pmc_val    = 0; /* clear all, bits 26-27 must be zero for proper operations */
		/* if plm is 0, then assume not specified per-event and use default */
		reg.pmc_plm    = inp->pfp_events[j].plm ? inp->pfp_events[j].plm : inp->pfp_dfl_plm;
		reg.pmc_oi     = 1; /* overflow interrupt */
		reg.pmc_pm     = inp->pfp_flags & PFMLIB_PFP_SYSTEMWIDE ? 1 : 0;
		reg.pmc_thres  = param ? param->pfp_ita2_counters[j].thres: 0;
		reg.pmc_ism    = param ? param->pfp_ita2_counters[j].ism : PFMLIB_ITA2_ISM_BOTH;
		reg.pmc_umask  = is_ear(e[j].event) ? 0x0 : itanium2_pe[e[j].event].pme_umask;
		reg.pmc_es     = itanium2_pe[e[j].event].pme_code;

		/*
		 * Note that we don't force PMC4.pmc_ena = 1 because the kernel takes care of this for us.
		 * This way we don't have to program something in PMC4 even when we don't use it
		 */
		pc[j].reg_num     = assign[j];
		pc[j].reg_value   = reg.pmc_val;
		pc[j].reg_addr    = pc[j].reg_alt_addr = assign[j];

		pd[j].reg_num  = assign[j];
		pd[j].reg_addr = pd[j].reg_addr = assign[j];

		__pfm_vbprintf("[PMC%u(pmc%u)=0x%06lx thres=%d es=0x%02x plm=%d umask=0x%x pm=%d ism=0x%x oi=%d] %s\n",
				assign[j],
				assign[j],
				reg.pmc_val,
				reg.pmc_thres,
				reg.pmc_es,reg.pmc_plm,
				reg.pmc_umask, reg.pmc_pm,
				reg.pmc_ism,
				reg.pmc_oi,
				itanium2_pe[e[j].event].pme_name);
		__pfm_vbprintf("[PMD%u(pmd%u)]\n", pd[j].reg_num, pd[j].reg_num);
	}
	/* number of PMC registers programmed */
	outp->pfp_pmc_count = cnt;
	outp->pfp_pmd_count = cnt;

	return PFMLIB_SUCCESS;
}

static int
pfm_dispatch_iear(pfmlib_input_param_t *inp, pfmlib_ita2_input_param_t *mod_in, pfmlib_output_param_t *outp)
{
	pfm_ita2_pmc_reg_t reg;
	pfmlib_ita2_input_param_t *param = mod_in;
	pfmlib_reg_t *pc, *pd;
	pfmlib_ita2_input_param_t fake_param;
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

	if (param == NULL || param->pfp_ita2_iear.ear_used == 0) {

		/*
		 * case 3: no I-EAR event, no (or nothing) in param->pfp_ita2_iear.ear_used
		 */
		if (i == count) return PFMLIB_SUCCESS;

		memset(&fake_param, 0, sizeof(fake_param));
		param = &fake_param;

		/*
		 * case 1: extract all information for event (name)
		 */
		pfm_ita2_get_ear_mode(inp->pfp_events[i].event, &param->pfp_ita2_iear.ear_mode);

		param->pfp_ita2_iear.ear_umask = evt_umask(inp->pfp_events[i].event);
		param->pfp_ita2_iear.ear_ism   = PFMLIB_ITA2_ISM_BOTH; /* force both instruction sets */

		DPRINT("I-EAR event with no info\n");
	}

	/*
	 * case 2: ear_used=1, event is defined, we use the param info as it is more precise
	 * case 4: ear_used=1, no event (free running I-EAR), use param info
	 */
	reg.pmc_val = 0;

	if (param->pfp_ita2_iear.ear_mode == PFMLIB_ITA2_EAR_TLB_MODE) {
		/* if plm is 0, then assume not specified per-event and use default */
		reg.pmc10_ita2_tlb_reg.iear_plm     = param->pfp_ita2_iear.ear_plm ? param->pfp_ita2_iear.ear_plm : inp->pfp_dfl_plm;
		reg.pmc10_ita2_tlb_reg.iear_pm      = inp->pfp_flags & PFMLIB_PFP_SYSTEMWIDE ? 1 : 0;
		reg.pmc10_ita2_tlb_reg.iear_ct      = 0x0;
		reg.pmc10_ita2_tlb_reg.iear_umask   = param->pfp_ita2_iear.ear_umask;
		reg.pmc10_ita2_tlb_reg.iear_ism     = param->pfp_ita2_iear.ear_ism;
	} else if (param->pfp_ita2_iear.ear_mode == PFMLIB_ITA2_EAR_CACHE_MODE) {
		/* if plm is 0, then assume not specified per-event and use default */
		reg.pmc10_ita2_cache_reg.iear_plm   = param->pfp_ita2_iear.ear_plm ? param->pfp_ita2_iear.ear_plm : inp->pfp_dfl_plm;
		reg.pmc10_ita2_cache_reg.iear_pm    = inp->pfp_flags & PFMLIB_PFP_SYSTEMWIDE ? 1 : 0;
		reg.pmc10_ita2_cache_reg.iear_ct    = 0x1;
		reg.pmc10_ita2_cache_reg.iear_umask = param->pfp_ita2_iear.ear_umask;
		reg.pmc10_ita2_cache_reg.iear_ism   = param->pfp_ita2_iear.ear_ism;
	} else {
		DPRINT("ALAT mode not supported in I-EAR mode\n");
		return PFMLIB_ERR_INVAL;
	}

	if (pfm_regmask_isset(&inp->pfp_unavail_pmcs, 10))
		return PFMLIB_ERR_NOASSIGN;

	pc[pos1].reg_num     = 10; /* PMC10 is I-EAR config register */
	pc[pos1].reg_value   = reg.pmc_val;
	pc[pos1].reg_addr  = pc[pos1].reg_alt_addr = 10;
	pos1++;
	pd[pos2].reg_num     = 0; 
	pd[pos2].reg_addr  = pd[pos2].reg_alt_addr= 0;
	pos2++;
	pd[pos2].reg_num     = 1; 
	pd[pos2].reg_addr  = pd[pos2].reg_alt_addr = 1;
	pos2++;

	if (param->pfp_ita2_iear.ear_mode == PFMLIB_ITA2_EAR_TLB_MODE) {
		__pfm_vbprintf("[PMC10(pmc10)=0x%lx ctb=tlb plm=%d pm=%d ism=0x%x umask=0x%x]\n",
			reg.pmc_val,
			reg.pmc10_ita2_tlb_reg.iear_plm,
			reg.pmc10_ita2_tlb_reg.iear_pm,
			reg.pmc10_ita2_tlb_reg.iear_ism,
			reg.pmc10_ita2_tlb_reg.iear_umask);
	} else {
		__pfm_vbprintf("[PMC10(pmc10)=0x%lx ctb=cache plm=%d pm=%d ism=0x%x umask=0x%x]\n",
			reg.pmc_val,
			reg.pmc10_ita2_cache_reg.iear_plm,
			reg.pmc10_ita2_cache_reg.iear_pm,
			reg.pmc10_ita2_cache_reg.iear_ism,
			reg.pmc10_ita2_cache_reg.iear_umask);
	}
	__pfm_vbprintf("[PMD0(pmd0)]\n[PMD1(pmd1)\n");

	/* update final number of entries used */
	outp->pfp_pmc_count = pos1;
	outp->pfp_pmd_count = pos2;

	return PFMLIB_SUCCESS;
}

static int
pfm_dispatch_dear(pfmlib_input_param_t *inp, pfmlib_ita2_input_param_t *mod_in, pfmlib_output_param_t *outp)
{
	pfm_ita2_pmc_reg_t reg;
	pfmlib_ita2_input_param_t *param = mod_in;
	pfmlib_reg_t *pc, *pd;
	pfmlib_ita2_input_param_t fake_param;
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

	if (param == NULL || param->pfp_ita2_dear.ear_used == 0) {

		/*
		 * case 3: no D-EAR event, no (or nothing) in param->pfp_ita2_dear.ear_used
		 */
		if (i == count) return PFMLIB_SUCCESS;

		memset(&fake_param, 0, sizeof(fake_param));
		param = &fake_param;

		/*
		 * case 1: extract all information for event (name)
		 */
		pfm_ita2_get_ear_mode(inp->pfp_events[i].event, &param->pfp_ita2_dear.ear_mode);

		param->pfp_ita2_dear.ear_umask = evt_umask(inp->pfp_events[i].event);
		param->pfp_ita2_dear.ear_ism   = PFMLIB_ITA2_ISM_BOTH; /* force both instruction sets */

		DPRINT("D-EAR event with no info\n");
	}

	/* sanity check on the mode */
	if (   param->pfp_ita2_dear.ear_mode != PFMLIB_ITA2_EAR_CACHE_MODE
	    && param->pfp_ita2_dear.ear_mode != PFMLIB_ITA2_EAR_TLB_MODE
	    && param->pfp_ita2_dear.ear_mode != PFMLIB_ITA2_EAR_ALAT_MODE)
		return PFMLIB_ERR_INVAL;

	/*
	 * case 2: ear_used=1, event is defined, we use the param info as it is more precise
	 * case 4: ear_used=1, no event (free running D-EAR), use param info
	 */
	reg.pmc_val = 0;

	/* if plm is 0, then assume not specified per-event and use default */
	reg.pmc11_ita2_reg.dear_plm   = param->pfp_ita2_dear.ear_plm ? param->pfp_ita2_dear.ear_plm : inp->pfp_dfl_plm;
	reg.pmc11_ita2_reg.dear_pm    = inp->pfp_flags & PFMLIB_PFP_SYSTEMWIDE ? 1 : 0;
	reg.pmc11_ita2_reg.dear_mode  = param->pfp_ita2_dear.ear_mode;
	reg.pmc11_ita2_reg.dear_umask = param->pfp_ita2_dear.ear_umask;
	reg.pmc11_ita2_reg.dear_ism   = param->pfp_ita2_dear.ear_ism;

	if (pfm_regmask_isset(&inp->pfp_unavail_pmcs, 11))
		return PFMLIB_ERR_NOASSIGN;

	pc[pos1].reg_num     = 11;  /* PMC11 is D-EAR config register */
	pc[pos1].reg_value   = reg.pmc_val;
	pc[pos1].reg_addr  = pc[pos1].reg_alt_addr = 11;
	pos1++;
	pd[pos2].reg_num     = 2; 
	pd[pos2].reg_addr  = pd[pos2].reg_alt_addr = 2;
	pos2++;
	pd[pos2].reg_num     = 3; 
	pd[pos2].reg_addr  = pd[pos2].reg_alt_addr = 3;
	pos2++;
	pd[pos2].reg_num     = 17; 
	pd[pos2].reg_addr  = pd[pos2].reg_alt_addr = 17;
	pos2++;

	__pfm_vbprintf("[PMC11(pmc11)=0x%lx mode=%s plm=%d pm=%d ism=0x%x umask=0x%x]\n",
			reg.pmc_val,
			reg.pmc11_ita2_reg.dear_mode == 0 ? "L1D" :
			(reg.pmc11_ita2_reg.dear_mode == 1 ? "L1DTLB" : "ALAT"),
			reg.pmc11_ita2_reg.dear_plm,	
			reg.pmc11_ita2_reg.dear_pm,
			reg.pmc11_ita2_reg.dear_ism,
			reg.pmc11_ita2_reg.dear_umask);
	__pfm_vbprintf("[PMD2(pmd2)]\n[PMD3(pmd3)\nPMD17(pmd17)\n");


	/* update final number of entries used */
	outp->pfp_pmc_count = pos1;
	outp->pfp_pmd_count = pos2;

	return PFMLIB_SUCCESS;
}

static int
pfm_dispatch_opcm(pfmlib_input_param_t *inp, pfmlib_ita2_input_param_t *mod_in, pfmlib_output_param_t *outp, pfmlib_ita2_output_param_t *mod_out)
{
	pfmlib_ita2_input_param_t *param = mod_in;
	pfmlib_reg_t *pc = outp->pfp_pmcs;
	pfm_ita2_pmc_reg_t reg, pmc15;
	unsigned int i, has_1st_pair, has_2nd_pair, count;
	unsigned int pos = outp->pfp_pmc_count;

	if (param == NULL) return PFMLIB_SUCCESS;

	/* not constrained by PMC8 nor PMC9 */
	pmc15.pmc_val = 0xffffffff; /* XXX: use PAL instead. PAL value is 0xfffffff0 */

	if (param->pfp_ita2_irange.rr_used && mod_out == NULL) return PFMLIB_ERR_INVAL;

	if (param->pfp_ita2_pmc8.opcm_used || (param->pfp_ita2_irange.rr_used && mod_out->pfp_ita2_irange.rr_nbr_used!=0) ) {

		reg.pmc_val = param->pfp_ita2_pmc8.opcm_used ? param->pfp_ita2_pmc8.pmc_val : 0xffffffff3fffffff;

		if (param->pfp_ita2_irange.rr_used) {
			reg.pmc8_9_ita2_reg.opcm_ig_ad = 0;
			reg.pmc8_9_ita2_reg.opcm_inv   = param->pfp_ita2_irange.rr_flags & PFMLIB_ITA2_RR_INV ? 1 : 0;
		} else {
			/* clear range restriction fields when none is used */
			reg.pmc8_9_ita2_reg.opcm_ig_ad = 1;
			reg.pmc8_9_ita2_reg.opcm_inv   = 0;
		}

		/* force bit 2 to 1 */
		reg.pmc8_9_ita2_reg.opcm_bit2 = 1;

		if (pfm_regmask_isset(&inp->pfp_unavail_pmcs, 8))
			return PFMLIB_ERR_NOASSIGN;

		pc[pos].reg_num     = 8;
		pc[pos].reg_value   = reg.pmc_val;
		pc[pos].reg_addr  = pc[pos].reg_addr = 8;
		pos++;

		/*
		 * will be constrained by PMC8
		 */
		if (param->pfp_ita2_pmc8.opcm_used) {
			has_1st_pair = has_2nd_pair = 0;
			count = inp->pfp_event_count;
			for(i=0; i < count; i++) {
				if (inp->pfp_events[i].event == PME_ITA2_IA64_TAGGED_INST_RETIRED_IBRP0_PMC8) has_1st_pair=1;
				if (inp->pfp_events[i].event == PME_ITA2_IA64_TAGGED_INST_RETIRED_IBRP2_PMC8) has_2nd_pair=1;
			}
			if (has_1st_pair || has_2nd_pair == 0) pmc15.pmc15_ita2_reg.opcmc_ibrp0_pmc8 = 0;
			if (has_2nd_pair || has_1st_pair == 0) pmc15.pmc15_ita2_reg.opcmc_ibrp2_pmc8 = 0;
		}

		__pfm_vbprintf("[PMC8(pmc8)=0x%lx m=%d i=%d f=%d b=%d match=0x%x mask=0x%x inv=%d ig_ad=%d]\n",
				reg.pmc_val,
				reg.pmc8_9_ita2_reg.opcm_m,
				reg.pmc8_9_ita2_reg.opcm_i,
				reg.pmc8_9_ita2_reg.opcm_f,
				reg.pmc8_9_ita2_reg.opcm_b,
				reg.pmc8_9_ita2_reg.opcm_match,
				reg.pmc8_9_ita2_reg.opcm_mask,
				reg.pmc8_9_ita2_reg.opcm_inv,
				reg.pmc8_9_ita2_reg.opcm_ig_ad);
	}

	if (param->pfp_ita2_pmc9.opcm_used) {
		/*
		 * PMC9 can only be used to qualify IA64_INST_RETIRED_* events
		 */
		if (check_inst_retired_events(inp, NULL) != inp->pfp_event_count) return PFMLIB_ERR_FEATCOMB;

		reg.pmc_val = param->pfp_ita2_pmc9.pmc_val;

		/* ig_ad, inv are ignored for PMC9, to avoid confusion we force default values */
		reg.pmc8_9_ita2_reg.opcm_ig_ad = 1;
		reg.pmc8_9_ita2_reg.opcm_inv   = 0;

		/* force bit 2 to 1 */
		reg.pmc8_9_ita2_reg.opcm_bit2 = 1;

		if (pfm_regmask_isset(&inp->pfp_unavail_pmcs, 9))
			return PFMLIB_ERR_NOASSIGN;

		pc[pos].reg_num    = 9;
		pc[pos].reg_value  = reg.pmc_val;
		pc[pos].reg_addr = pc[pos].reg_alt_addr = 9;
		pos++;

		/*
		 * will be constrained by PMC9
		 */
		has_1st_pair = has_2nd_pair = 0;

		count = inp->pfp_event_count;
		for(i=0; i < count; i++) {
			if (inp->pfp_events[i].event == PME_ITA2_IA64_TAGGED_INST_RETIRED_IBRP1_PMC9) has_1st_pair=1;
			if (inp->pfp_events[i].event == PME_ITA2_IA64_TAGGED_INST_RETIRED_IBRP3_PMC9) has_2nd_pair=1;
		}
		if (has_1st_pair || has_2nd_pair == 0) pmc15.pmc15_ita2_reg.opcmc_ibrp1_pmc9 = 0;
		if (has_2nd_pair || has_1st_pair == 0) pmc15.pmc15_ita2_reg.opcmc_ibrp3_pmc9 = 0;

		__pfm_vbprintf("[PMC9(pmc9)=0x%lx m=%d i=%d f=%d b=%d match=0x%x mask=0x%x]\n",
				reg.pmc_val,
				reg.pmc8_9_ita2_reg.opcm_m,
				reg.pmc8_9_ita2_reg.opcm_i,
				reg.pmc8_9_ita2_reg.opcm_f,
				reg.pmc8_9_ita2_reg.opcm_b,
				reg.pmc8_9_ita2_reg.opcm_match,
				reg.pmc8_9_ita2_reg.opcm_mask);

	}

	if (pfm_regmask_isset(&inp->pfp_unavail_pmcs, 15))
		return PFMLIB_ERR_NOASSIGN;

	pc[pos].reg_num    = 15;
	pc[pos].reg_value  = pmc15.pmc_val;
	pc[pos].reg_addr = pc[pos].reg_alt_addr = 15;
	pos++;

	__pfm_vbprintf("[PMC15(pmc15)=0x%lx ibrp0_pmc8=%d ibrp1_pmc9=%d ibrp2_pmc8=%d ibrp3_pmc9=%d]\n",
			pmc15.pmc_val,
			pmc15.pmc15_ita2_reg.opcmc_ibrp0_pmc8,
			pmc15.pmc15_ita2_reg.opcmc_ibrp1_pmc9,
			pmc15.pmc15_ita2_reg.opcmc_ibrp2_pmc8,
			pmc15.pmc15_ita2_reg.opcmc_ibrp3_pmc9);

	outp->pfp_pmc_count = pos;

	return PFMLIB_SUCCESS;
}


static int
pfm_dispatch_btb(pfmlib_input_param_t *inp, pfmlib_ita2_input_param_t *mod_in, pfmlib_output_param_t *outp)
{
	pfmlib_event_t *e= inp->pfp_events;
	pfm_ita2_pmc_reg_t reg;
	pfmlib_ita2_input_param_t *param = mod_in;
	pfmlib_reg_t *pc, *pd;
	pfmlib_ita2_input_param_t fake_param;
	int found_btb = 0, found_bad_dear = 0;
	int has_btb_param;
	unsigned int i, pos1, pos2;
	unsigned int count;

	pc = outp->pfp_pmcs;
	pd = outp->pfp_pmds;
	pos1 = outp->pfp_pmc_count;
	pos2 = outp->pfp_pmd_count;


	/*
	 * explicit BTB settings
	 */
	has_btb_param = param && param->pfp_ita2_btb.btb_used;

	reg.pmc_val = 0UL;

	/*
	 * we need to scan all events looking for DEAR ALAT/TLB due to incompatibility
	 */
	count = inp->pfp_event_count;
	for (i=0; i < count; i++) {

		if (is_btb(e[i].event)) found_btb = 1;

		/*
		 * keep track of the first BTB event
		 */

		/* look only for DEAR TLB */
		if (is_dear(e[i].event) && (is_ear_tlb(e[i].event) || is_ear_alat(e[i].event))) {
			found_bad_dear = 1;
		}
	}

	DPRINT("found_btb=%d found_bar_dear=%d\n", found_btb, found_bad_dear);

	/*
	 * did not find D-EAR TLB/ALAT event, need to check param structure
	 */
	if (found_bad_dear == 0 && param && param->pfp_ita2_dear.ear_used == 1) {
		if (   param->pfp_ita2_dear.ear_mode == PFMLIB_ITA2_EAR_TLB_MODE
		    || param->pfp_ita2_dear.ear_mode == PFMLIB_ITA2_EAR_ALAT_MODE)
			found_bad_dear = 1;
	}

	/*
	 * no explicit BTB event and no special case to deal with (cover part of case 3)
	 */
	if (found_btb == 0 && has_btb_param == 0 && found_bad_dear == 0) return PFMLIB_SUCCESS;

	if (has_btb_param == 0) {

		/*
		 * case 3: no BTB event, btb_used=0 but found_bad_dear=1, need to cleanup PMC12
		 */
		 if (found_btb == 0) goto assign_zero;

		/*
		 * case 1: we have a BTB event but no param, default setting is to capture
		 *         all branches.
		 */
		memset(&fake_param, 0, sizeof(fake_param));
		param = &fake_param;

		param->pfp_ita2_btb.btb_ds  = 0; 	/* capture branch targets */
		param->pfp_ita2_btb.btb_tm  = 0x3; 	/* all branches */
		param->pfp_ita2_btb.btb_ptm = 0x3; 	/* all branches */
		param->pfp_ita2_btb.btb_ppm = 0x3; 	/* all branches */
		param->pfp_ita2_btb.btb_brt = 0x0; 	/* all branches */

		DPRINT("BTB event with no info\n");
	}

	/*
	 * case 2: BTB event in the list, param provided
	 * case 4: no BTB event, param provided (free running mode)
	 */
	reg.pmc12_ita2_reg.btbc_plm = param->pfp_ita2_btb.btb_plm ? param->pfp_ita2_btb.btb_plm : inp->pfp_dfl_plm;
	reg.pmc12_ita2_reg.btbc_pm  = inp->pfp_flags & PFMLIB_PFP_SYSTEMWIDE ? 1 : 0;
	reg.pmc12_ita2_reg.btbc_ds  = param->pfp_ita2_btb.btb_ds & 0x1;
	reg.pmc12_ita2_reg.btbc_tm  = param->pfp_ita2_btb.btb_tm & 0x3;
	reg.pmc12_ita2_reg.btbc_ptm = param->pfp_ita2_btb.btb_ptm & 0x3;
	reg.pmc12_ita2_reg.btbc_ppm = param->pfp_ita2_btb.btb_ppm & 0x3;
	reg.pmc12_ita2_reg.btbc_brt = param->pfp_ita2_btb.btb_brt & 0x3;

	/*
	 * if DEAR-ALAT or DEAR-TLB is set then PMC12 must be set to zero (see documentation p. 87)
	 *
	 * D-EAR ALAT/TLB and BTB cannot be used at the same time.
	 * From documentation: PMC12 must be zero in this mode; else the wrong IP for misses
	 * coming right after a mispredicted branch.
	 *
	 * D-EAR cache is fine.
	 */
assign_zero:
	if (found_bad_dear && reg.pmc_val != 0UL) return PFMLIB_ERR_EVTINCOMP;

	if (pfm_regmask_isset(&inp->pfp_unavail_pmcs, 12))
		return PFMLIB_ERR_NOASSIGN;

	memset(pc+pos1, 0, sizeof(pfmlib_reg_t));

	pc[pos1].reg_num   = 12;
	pc[pos1].reg_value = reg.pmc_val;
	pc[pos1].reg_addr  = pc[pos1].reg_alt_addr = 12;
	pos1++;

	__pfm_vbprintf("[PMC12(pmc12)=0x%lx plm=%d pm=%d ds=%d tm=%d ptm=%d ppm=%d brt=%d]\n",
				reg.pmc_val,
				reg.pmc12_ita2_reg.btbc_plm,
				reg.pmc12_ita2_reg.btbc_pm,
				reg.pmc12_ita2_reg.btbc_ds,
				reg.pmc12_ita2_reg.btbc_tm,
				reg.pmc12_ita2_reg.btbc_ptm,
				reg.pmc12_ita2_reg.btbc_ppm,
				reg.pmc12_ita2_reg.btbc_brt);
	/*
	 * only add BTB PMD when actually using BTB.
	 * Not needed when dealing with D-EAR TLB and DEAR-ALAT
	 * PMC12 restriction
	 */
	if (found_btb || has_btb_param) {
		/*
		 * PMD16 is included in list of used PMD
		 */
		for(i=8; i < 17; i++, pos2++) {
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


	br[*idx].reg_num     = *reg_idx;
	br[*idx].reg_value   = l_addr;
	br[*idx].reg_addr    = br[*idx].reg_alt_addr = *reg_idx;

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
print_one_range(pfmlib_ita2_input_rr_desc_t *in_rr, pfmlib_ita2_output_rr_desc_t *out_rr, pfmlib_reg_t *dbr, int base_idx, int n_pairs, int fine_mode, unsigned int rr_flags)
{
	int j;
	dbreg_t d;
	unsigned long r_end;

	__pfm_vbprintf("[0x%lx-0x%lx): %d register pair(s)%s%s\n",
			in_rr->rr_start, in_rr->rr_end,
			n_pairs,
			fine_mode ? ", fine_mode" : "",
			rr_flags & PFMLIB_ITA2_RR_INV ? ", inversed" : "");

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
compute_fine_rr(pfmlib_ita2_input_rr_t *irr, int dfl_plm, int n, int *base_idx, pfmlib_ita2_output_rr_t *orr)
{
	int i;
	pfmlib_reg_t *br;
	pfmlib_ita2_input_rr_desc_t *in_rr;
	pfmlib_ita2_output_rr_desc_t *out_rr;
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
		 * because of the PMU bug, we must align down to the closest bundle-pair
		 * aligned address. 5 => 32-byte aligned address
		 */
		addr            = has_fine_mode_bug ? ALIGN_DOWN(in_rr->rr_start, 5) : in_rr->rr_start;
		out_rr->rr_soff = in_rr->rr_start - addr;

		/*
		 * adjust plm for each range
		 */
		db.db.db_plm    = in_rr->rr_plm ? in_rr->rr_plm : (unsigned long)dfl_plm;

		br[0].reg_num   = reg_idx;
		br[0].reg_value = addr;
		br[0].reg_addr  = br[0].reg_alt_addr = reg_idx;
		br[1].reg_num   = reg_idx+1;
		br[1].reg_value = db.val;
		br[1].reg_addr  = br[1].reg_alt_addr = reg_idx+1;

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

		if (has_fine_mode_bug && (addr & 0x1f) == 0) addr += 0x10;
		out_rr->rr_eoff = addr - in_rr->rr_end + 0x10;

		br[2].reg_num   = reg_idx+4;
		br[2].reg_value = addr;
		br[2].reg_addr  = br[2].reg_alt_addr = reg_idx+4;

		br[3].reg_num   = reg_idx+5;
		br[3].reg_value = db.val;
		br[3].reg_addr  = br[3].reg_alt_addr = reg_idx+5;

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
compute_single_rr(pfmlib_ita2_input_rr_t *irr, int dfl_plm, int *base_idx, pfmlib_ita2_output_rr_t *orr)
{
	unsigned long size, end, start;
	unsigned long p_start, p_end;
	pfmlib_ita2_input_rr_desc_t *in_rr;
	pfmlib_ita2_output_rr_desc_t *out_rr;
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
	br[0].reg_addr  =  br[0].reg_alt_addr = reg_idx;

	db.val        = 0;
	db.db.db_mask = ~((1UL << m)-1);
	db.db.db_plm  = in_rr->rr_plm ? in_rr->rr_plm : (unsigned long)dfl_plm;


	br[1].reg_num   = reg_idx + 1;
	br[1].reg_value = db.val;
	br[1].reg_addr  = br[1].reg_alt_addr = reg_idx + 1;

	out_rr->rr_soff = start - p_start;
	out_rr->rr_eoff = p_end - end;

	if (PFMLIB_VERBOSE()) print_one_range(in_rr, out_rr, br, 0, 1, 0, irr->rr_flags);

	orr->rr_nbr_used += 2;

	/* update base_idx, for subsequent calls */
	*base_idx = reg_idx;

	return PFMLIB_SUCCESS;
}

static int
compute_normal_rr(pfmlib_ita2_input_rr_t *irr, int dfl_plm, int n, int *base_idx, pfmlib_ita2_output_rr_t *orr)
{
	pfmlib_ita2_input_rr_desc_t *in_rr;
	pfmlib_ita2_output_rr_desc_t *out_rr;
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
pfm_dispatch_irange(pfmlib_input_param_t *inp, pfmlib_ita2_input_param_t *mod_in, pfmlib_output_param_t *outp, pfmlib_ita2_output_param_t *mod_out)
{
	pfm_ita2_pmc_reg_t reg;
	pfmlib_ita2_input_param_t *param = mod_in;
	pfmlib_ita2_input_rr_t *irr;
	pfmlib_ita2_output_rr_t *orr;
	pfmlib_reg_t *pc = outp->pfp_pmcs;
	unsigned int i, pos = outp->pfp_pmc_count, count;
	int ret;
	unsigned int retired_only, retired_count, fine_mode, prefetch_count;
	unsigned int n_intervals;
	int base_idx = 0;
	unsigned long retired_mask;

	if (param == NULL) return PFMLIB_SUCCESS;

	if (param->pfp_ita2_irange.rr_used == 0) return PFMLIB_SUCCESS;

	if (mod_out == NULL) return PFMLIB_ERR_INVAL;

	irr = &param->pfp_ita2_irange;
	orr = &mod_out->pfp_ita2_irange;

	ret = check_intervals(irr, 0, &n_intervals);
	if (ret != PFMLIB_SUCCESS) return ret;

	if (n_intervals < 1) return PFMLIB_ERR_IRRINVAL;
	
	retired_count  = check_inst_retired_events(inp, &retired_mask);
	retired_only   = retired_count == inp->pfp_event_count;
	prefetch_count = check_prefetch_events(inp);
	fine_mode      = irr->rr_flags & PFMLIB_ITA2_RR_NO_FINE_MODE ?
		         0 : check_fine_mode_possible(irr, n_intervals);

	DPRINT("n_intervals=%d retired_only=%d retired_count=%d prefetch_count=%d fine_mode=%d\n",
		n_intervals, retired_only, retired_count, prefetch_count, fine_mode);

	/*
	 * On Itanium2, there are more constraints on what can be measured with irange.
	 *
	 * - The fine mode is the best because you directly set the lower and upper limits of
	 *   the range. This uses 2 ibr pairs for range (ibrp0/ibrp2 and ibp1/ibrp3). Therefore
	 *   at most 2 fine mode ranges can be defined. There is a limit on the size and alignment
	 *   of the range to allow fine mode: the range must be less than 4KB in size AND the lower
	 *   and upper limits must NOT cross a 4KB page boundary. The fine mode works will all events.
	 *
	 * - if the fine mode fails, then for all events, except IA64_TAGGED_INST_RETIRED_*, only
	 *   the first pair of ibr is available: ibrp0. This imposes some severe restrictions on the
	 *   size and alignment of the range. It can be bigger than 4KB and must be properly aligned
	 *   on its size. The library relaxes these constraints by allowing the covered areas to be
	 *   larger than the expected range. It may start before and end after. You can determine how
	 *   far off the range is in either direction for each range by looking at the rr_soff (start
	 *   offset) and rr_eoff (end offset).
	 *
	 * - if the events include certain prefetch events then only IBRP1 can be used in fine mode
	 *   See 10.3.5.1 Exception 1.
	 *
	 * - Finally, when the events are ONLY IA64_TAGGED_INST_RETIRED_* then all IBR pairs can be used
	 *   to cover the range giving us more flexibility to approximate the range when it is not
	 *   properly aligned on its size (see 10.3.5.2 Exception 2).
	 */

	if (fine_mode == 0 && retired_only == 0 && n_intervals > 1) return PFMLIB_ERR_IRRTOOMANY;

	/* we do not default to non-fine mode to support more ranges */
	if (n_intervals > 2 && fine_mode == 1) return PFMLIB_ERR_IRRTOOMANY;

	if (fine_mode == 0) {
		if (retired_only) {
			ret = compute_normal_rr(irr, inp->pfp_dfl_plm, n_intervals, &base_idx, orr);
		} else {
			/* unless we have only prefetch and instruction retired events,
			 * we cannot satisfy the request because the other events cannot
			 * be measured on anything but IBRP0.
			 */
			if (prefetch_count && (prefetch_count+retired_count) != inp->pfp_event_count)
				return PFMLIB_ERR_FEATCOMB;

			base_idx =  prefetch_count ? 2 : 0;

			ret = compute_single_rr(irr, inp->pfp_dfl_plm, &base_idx, orr);
		}
	} else {
		if (prefetch_count && n_intervals != 1) return PFMLIB_ERR_IRRTOOMANY;

		base_idx = prefetch_count ? 2 : 0;
		ret = compute_fine_rr(irr, inp->pfp_dfl_plm, n_intervals, &base_idx, orr);
	}

	if (ret != PFMLIB_SUCCESS) {
		return ret == PFMLIB_ERR_TOOMANY ? PFMLIB_ERR_IRRTOOMANY : ret;
	}

	reg.pmc_val = 0xdb6; /* default value */

	count = orr->rr_nbr_used;
	for (i=0; i < count; i++) {
		switch(orr->rr_br[i].reg_num) {
			case 0:
				reg.pmc14_ita2_reg.iarc_ibrp0 = 0;
				break;
			case 2:
				reg.pmc14_ita2_reg.iarc_ibrp1 = 0;
				break;
			case 4: 
				reg.pmc14_ita2_reg.iarc_ibrp2 = 0;
				break;
			case 6:
				reg.pmc14_ita2_reg.iarc_ibrp3 = 0;
				break;
		}
	}

	if (retired_only && (param->pfp_ita2_pmc8.opcm_used ||param->pfp_ita2_pmc9.opcm_used)) {
		/*
		 * PMC8 + IA64_INST_RETIRED only works if irange on IBRP0 and/or IBRP2
		 * PMC9 + IA64_INST_RETIRED only works if irange on IBRP1 and/or IBRP3
		 */
		count = orr->rr_nbr_used;
		for (i=0; i < count; i++) {
			if (orr->rr_br[i].reg_num == 0 && param->pfp_ita2_pmc9.opcm_used)  return PFMLIB_ERR_FEATCOMB;
			if (orr->rr_br[i].reg_num == 2 && param->pfp_ita2_pmc8.opcm_used)  return PFMLIB_ERR_FEATCOMB;
			if (orr->rr_br[i].reg_num == 4 && param->pfp_ita2_pmc9.opcm_used)  return PFMLIB_ERR_FEATCOMB;
			if (orr->rr_br[i].reg_num == 6 && param->pfp_ita2_pmc8.opcm_used)  return PFMLIB_ERR_FEATCOMB;
		}
	}

	if (fine_mode) {
		reg.pmc14_ita2_reg.iarc_fine = 1;
	} else if (retired_only) {
		/*
		 * we need to check that the user provided all the events needed to cover
		 * all the ibr pairs used to cover the range
		 */
		if ((retired_mask & 0x1) == 0 &&  reg.pmc14_ita2_reg.iarc_ibrp0 == 0) return PFMLIB_ERR_IRRINVAL;
		if ((retired_mask & 0x2) == 0 &&  reg.pmc14_ita2_reg.iarc_ibrp1 == 0) return PFMLIB_ERR_IRRINVAL;
		if ((retired_mask & 0x4) == 0 &&  reg.pmc14_ita2_reg.iarc_ibrp2 == 0) return PFMLIB_ERR_IRRINVAL;
		if ((retired_mask & 0x8) == 0 &&  reg.pmc14_ita2_reg.iarc_ibrp3 == 0) return PFMLIB_ERR_IRRINVAL;
	}

	/* initialize pmc request slot */
	memset(pc+pos, 0, sizeof(pfmlib_reg_t));

	if (pfm_regmask_isset(&inp->pfp_unavail_pmcs, 14))
		return PFMLIB_ERR_NOASSIGN;

	pc[pos].reg_num     = 14;
	pc[pos].reg_value   = reg.pmc_val;
	pc[pos].reg_addr  = pc[pos].reg_alt_addr = 14;
	pos++;

	__pfm_vbprintf("[PMC14(pmc14)=0x%lx ibrp0=%d ibrp1=%d ibrp2=%d ibrp3=%d fine=%d]\n",
			reg.pmc_val,
			reg.pmc14_ita2_reg.iarc_ibrp0,
			reg.pmc14_ita2_reg.iarc_ibrp1,
			reg.pmc14_ita2_reg.iarc_ibrp2,
			reg.pmc14_ita2_reg.iarc_ibrp3,
			reg.pmc14_ita2_reg.iarc_fine);

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
 * the irange programming to adjust pmc13.
 */
static int
pfm_dispatch_drange(pfmlib_input_param_t *inp, pfmlib_ita2_input_param_t *mod_in, pfmlib_output_param_t *outp, pfmlib_ita2_output_param_t *mod_out)
{
	pfmlib_ita2_input_param_t *param = mod_in;
	pfmlib_reg_t *pc = outp->pfp_pmcs;
	pfmlib_ita2_input_rr_t *irr;
	pfmlib_ita2_output_rr_t *orr, *orr2;
	pfm_ita2_pmc_reg_t pmc13;
	pfm_ita2_pmc_reg_t pmc14;
	unsigned int i, pos = outp->pfp_pmc_count;
	int iod_codes[4], dfl_val_pmc8, dfl_val_pmc9;
	unsigned int n_intervals;
	int ret;
	int base_idx = 0;
	int fine_mode = 0;
#define DR_USED	0x1 /* data range is used */
#define OP_USED	0x2 /* opcode matching is used */
#define IR_USED	0x4 /* code range is used */

	if (param == NULL) return PFMLIB_SUCCESS;
	/*
	 * if only pmc8/pmc9 opcode matching is used, we do not need to change
	 * the default value of pmc13 regardless of the events being measured.
	 */
	if (  param->pfp_ita2_drange.rr_used == 0
	   && param->pfp_ita2_irange.rr_used == 0) return PFMLIB_SUCCESS;

	/*
	 * it seems like the ignored bits need to have special values
	 * otherwise this does not work.
	 */
	pmc13.pmc_val = 0x2078fefefefe;

	/*
	 * initialize iod codes
	 */
	iod_codes[0] = iod_codes[1] = iod_codes[2] = iod_codes[3] = 0;

	/*
	 * setup default iod value, we need to separate because
	 * if drange is used we do not know in advance which DBR will be used
	 * therefore we need to apply dfl_val later
	 */
	dfl_val_pmc8 = param->pfp_ita2_pmc8.opcm_used ? OP_USED : 0;
	dfl_val_pmc9 = param->pfp_ita2_pmc9.opcm_used ? OP_USED : 0;

	if (param->pfp_ita2_drange.rr_used == 1) {

		if (mod_out == NULL) return PFMLIB_ERR_INVAL;

		irr = &param->pfp_ita2_drange;
		orr = &mod_out->pfp_ita2_drange;

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
			if (orr->rr_br[i].reg_num == 0) iod_codes[0] |= DR_USED | dfl_val_pmc8;
			if (orr->rr_br[i].reg_num == 2) iod_codes[1] |= DR_USED | dfl_val_pmc9;
			if (orr->rr_br[i].reg_num == 4) iod_codes[2] |= DR_USED | dfl_val_pmc8;
			if (orr->rr_br[i].reg_num == 6) iod_codes[3] |= DR_USED | dfl_val_pmc9;
		}

	}

	/*
	 * XXX: assume dispatch_irange executed before calling this function
	 */
	if (param->pfp_ita2_irange.rr_used == 1) {

		orr2 = &mod_out->pfp_ita2_irange;

		if (mod_out == NULL) return PFMLIB_ERR_INVAL;

		/*
		 * we need to find out whether or not the irange is using
		 * fine mode. If this is the case, then we only need to
		 * program pmc13 for the ibr pairs which designate the lower
		 * bounds of a range. For instance, if IBRP0/IBRP2 are used,
		 * then we only need to program pmc13.cfg_dbrp0 and pmc13.ena_dbrp0,
		 * the PMU will automatically use IBRP2, even though pmc13.ena_dbrp2=0.
		 */
		for(i=0; i <= pos; i++) {
			if (pc[i].reg_num == 14) {
				pmc14.pmc_val = pc[i].reg_value;
				if (pmc14.pmc14_ita2_reg.iarc_fine == 1) fine_mode = 1;
				break;
			}
		}

		/*
		 * Update to reflect the use of the IBR constraint
		 */
		for (i=0; i < orr2->rr_nbr_used; i++) {
			if (orr2->rr_br[i].reg_num == 0) iod_codes[0] |= IR_USED | dfl_val_pmc8;
			if (orr2->rr_br[i].reg_num == 2) iod_codes[1] |= IR_USED | dfl_val_pmc9;
			if (fine_mode == 0 && orr2->rr_br[i].reg_num == 4) iod_codes[2] |= IR_USED | dfl_val_pmc8;
			if (fine_mode == 0 && orr2->rr_br[i].reg_num == 6) iod_codes[3] |= IR_USED | dfl_val_pmc9;
		}
	}

	if (param->pfp_ita2_irange.rr_used == 0 && param->pfp_ita2_drange.rr_used ==0) {
		iod_codes[0] = iod_codes[2] = dfl_val_pmc8;
		iod_codes[1] = iod_codes[3] = dfl_val_pmc9;
	}

	/*
	 * update the cfg dbrpX field. If we put a constraint on a cfg dbrp, then
	 * we must enable it in the corresponding ena_dbrpX
	 */
	pmc13.pmc13_ita2_reg.darc_ena_dbrp0 = iod_codes[0] ? 1 : 0;
	pmc13.pmc13_ita2_reg.darc_cfg_dbrp0 = iod_tab[iod_codes[0]];

	pmc13.pmc13_ita2_reg.darc_ena_dbrp1 = iod_codes[1] ? 1 : 0;
	pmc13.pmc13_ita2_reg.darc_cfg_dbrp1 = iod_tab[iod_codes[1]];

	pmc13.pmc13_ita2_reg.darc_ena_dbrp2 = iod_codes[2] ? 1 : 0;
	pmc13.pmc13_ita2_reg.darc_cfg_dbrp2 = iod_tab[iod_codes[2]];

	pmc13.pmc13_ita2_reg.darc_ena_dbrp3 = iod_codes[3] ? 1 : 0;
	pmc13.pmc13_ita2_reg.darc_cfg_dbrp3 = iod_tab[iod_codes[3]];


	if (pfm_regmask_isset(&inp->pfp_unavail_pmcs, 13))
		return PFMLIB_ERR_NOASSIGN;

	pc[pos].reg_num     = 13;
	pc[pos].reg_value   = pmc13.pmc_val;
	pc[pos].reg_addr  = pc[pos].reg_alt_addr = 13;
	pos++;

	__pfm_vbprintf("[PMC13(pmc13)=0x%lx cfg_dbrp0=%d cfg_dbrp1=%d cfg_dbrp2=%d cfg_dbrp3=%d ena_dbrp0=%d ena_dbrp1=%d ena_dbrp2=%d ena_dbrp3=%d]\n",
			pmc13.pmc_val,
			pmc13.pmc13_ita2_reg.darc_cfg_dbrp0,
			pmc13.pmc13_ita2_reg.darc_cfg_dbrp1,
			pmc13.pmc13_ita2_reg.darc_cfg_dbrp2,
			pmc13.pmc13_ita2_reg.darc_cfg_dbrp3,
			pmc13.pmc13_ita2_reg.darc_ena_dbrp0,
			pmc13.pmc13_ita2_reg.darc_ena_dbrp1,
			pmc13.pmc13_ita2_reg.darc_ena_dbrp2,
			pmc13.pmc13_ita2_reg.darc_ena_dbrp3);

	outp->pfp_pmc_count = pos;

	return PFMLIB_SUCCESS;
}

static int
check_qualifier_constraints(pfmlib_input_param_t *inp, pfmlib_ita2_input_param_t *mod_in)
{
	pfmlib_ita2_input_param_t *param = mod_in;
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
		if (param->pfp_ita2_counters[i].flags & PFMLIB_ITA2_FL_EVT_NO_QUALCHECK) continue;


		if (evt_use_irange(param) && has_iarr(e[i].event) == 0) return PFMLIB_ERR_FEATCOMB;
		if (evt_use_drange(param) && has_darr(e[i].event) == 0) return PFMLIB_ERR_FEATCOMB;
		if (evt_use_opcm(param) && has_opcm(e[i].event) == 0) return PFMLIB_ERR_FEATCOMB;
	}
	return PFMLIB_SUCCESS;
}

static int
check_range_plm(pfmlib_input_param_t *inp, pfmlib_ita2_input_param_t *mod_in)
{
	pfmlib_ita2_input_param_t *param = mod_in;
	unsigned int i, count;

	if (param->pfp_ita2_drange.rr_used == 0 && param->pfp_ita2_irange.rr_used == 0) return PFMLIB_SUCCESS;

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
pfm_ita2_dispatch_events(pfmlib_input_param_t *inp, void *model_in, pfmlib_output_param_t *outp, void *model_out)
{
	int ret;
	pfmlib_ita2_input_param_t *mod_in  = (pfmlib_ita2_input_param_t *)model_in;
	pfmlib_ita2_output_param_t *mod_out = (pfmlib_ita2_output_param_t *)model_out;

	/*
	 * nothing will come out of this combination
	 */
	if (mod_out && mod_in == NULL) return PFMLIB_ERR_INVAL;

	/* check opcode match, range restriction qualifiers */
	if (mod_in && check_qualifier_constraints(inp, mod_in) != PFMLIB_SUCCESS) return PFMLIB_ERR_FEATCOMB;

	/* check for problems with raneg restriction and per-event plm */
	if (mod_in && check_range_plm(inp, mod_in) != PFMLIB_SUCCESS) return PFMLIB_ERR_FEATCOMB;

	ret = pfm_ita2_dispatch_counters(inp, mod_in, outp);
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

	ret = pfm_dispatch_btb(inp, mod_in, outp);

	return ret;
}


/* XXX: return value is also error code */
int
pfm_ita2_get_event_maxincr(unsigned int i, unsigned int *maxincr)
{
	if (i >= PME_ITA2_EVENT_COUNT || maxincr == NULL) return PFMLIB_ERR_INVAL;
	*maxincr = itanium2_pe[i].pme_maxincr;
	return PFMLIB_SUCCESS;
}

int
pfm_ita2_is_ear(unsigned int i)
{
	return i < PME_ITA2_EVENT_COUNT && is_ear(i);
}

int
pfm_ita2_is_dear(unsigned int i)
{
	return i < PME_ITA2_EVENT_COUNT && is_dear(i);
}

int
pfm_ita2_is_dear_tlb(unsigned int i)
{
	return i < PME_ITA2_EVENT_COUNT && is_dear(i) && is_ear_tlb(i);
}
	
int
pfm_ita2_is_dear_cache(unsigned int i)
{
	return i < PME_ITA2_EVENT_COUNT && is_dear(i) && is_ear_cache(i);
}

int
pfm_ita2_is_dear_alat(unsigned int i)
{
	return i < PME_ITA2_EVENT_COUNT && is_ear_alat(i);
}
	
int
pfm_ita2_is_iear(unsigned int i)
{
	return i < PME_ITA2_EVENT_COUNT && is_iear(i);
}

int
pfm_ita2_is_iear_tlb(unsigned int i)
{
	return i < PME_ITA2_EVENT_COUNT && is_iear(i) && is_ear_tlb(i);
}
	
int
pfm_ita2_is_iear_cache(unsigned int i)
{
	return i < PME_ITA2_EVENT_COUNT && is_iear(i) && is_ear_cache(i);
}
	
int
pfm_ita2_is_btb(unsigned int i)
{
	return i < PME_ITA2_EVENT_COUNT && is_btb(i);
}

int
pfm_ita2_support_iarr(unsigned int i)
{
	return i < PME_ITA2_EVENT_COUNT && has_iarr(i);
}


int
pfm_ita2_support_darr(unsigned int i)
{
	return i < PME_ITA2_EVENT_COUNT  && has_darr(i);
}


int
pfm_ita2_support_opcm(unsigned int i)
{
	return i < PME_ITA2_EVENT_COUNT && has_opcm(i);
}

int
pfm_ita2_get_ear_mode(unsigned int i, pfmlib_ita2_ear_mode_t *m)
{
	pfmlib_ita2_ear_mode_t r;

	if (!is_ear(i) || m == NULL) return PFMLIB_ERR_INVAL;

	r = PFMLIB_ITA2_EAR_TLB_MODE;
	if (is_ear_tlb(i))  goto done;

	r = PFMLIB_ITA2_EAR_CACHE_MODE;
	if (is_ear_cache(i))  goto done;

	r = PFMLIB_ITA2_EAR_ALAT_MODE;
	if (is_ear_alat(i)) goto done;

	return PFMLIB_ERR_INVAL;
done:
	*m = r;
	return PFMLIB_SUCCESS;
}

static int
pfm_ita2_get_event_code(unsigned int i, unsigned int cnt, int *code)
{
	if (cnt != PFMLIB_CNT_FIRST && (cnt < 4 || cnt > 7))
		return PFMLIB_ERR_INVAL;

	*code = (int)itanium2_pe[i].pme_code;

	return PFMLIB_SUCCESS;
}

/*
 * This function is accessible directly to the user
 */
int
pfm_ita2_get_event_umask(unsigned int i, unsigned long *umask)
{
	if (i >= PME_ITA2_EVENT_COUNT || umask == NULL) return PFMLIB_ERR_INVAL;
	*umask = evt_umask(i);
	return PFMLIB_SUCCESS;
}
	
int
pfm_ita2_get_event_group(unsigned int i, int *grp)
{
	if (i >= PME_ITA2_EVENT_COUNT || grp == NULL) return PFMLIB_ERR_INVAL;
	*grp = evt_grp(i);
	return PFMLIB_SUCCESS;
}

int
pfm_ita2_get_event_set(unsigned int i, int *set)
{
	if (i >= PME_ITA2_EVENT_COUNT || set == NULL) return PFMLIB_ERR_INVAL;
	*set = evt_set(i) == 0xf ? PFMLIB_ITA2_EVT_NO_SET : evt_set(i);
	return PFMLIB_SUCCESS;
}

/* external interface */
int
pfm_ita2_irange_is_fine(pfmlib_output_param_t *outp, pfmlib_ita2_output_param_t *mod_out)
{
	pfmlib_ita2_output_param_t *param = mod_out;
	pfm_ita2_pmc_reg_t reg;
	unsigned int i, count;

	/* some sanity checks */
	if (outp == NULL || param == NULL) return 0;
	if (outp->pfp_pmc_count >= PFMLIB_MAX_PMCS) return 0;

	if (param->pfp_ita2_irange.rr_nbr_used == 0) return 0;

	/*
	 * we look for pmc14 as it contains the bit indicating if fine mode is used
	 */
	count = outp->pfp_pmc_count;
	for(i=0; i < count; i++) {
		if (outp->pfp_pmcs[i].reg_num == 14) goto found;
	}
	return 0;
found:
	reg.pmc_val = outp->pfp_pmcs[i].reg_value;
	return reg.pmc14_ita2_reg.iarc_fine ? 1 : 0;
}

static char *
pfm_ita2_get_event_name(unsigned int i)
{
	return itanium2_pe[i].pme_name;
}

static void
pfm_ita2_get_event_counters(unsigned int j, pfmlib_regmask_t *counters)
{
	unsigned int i;
	unsigned long m;

	memset(counters, 0, sizeof(*counters));

	m =itanium2_pe[j].pme_counters;
	for(i=0; m ; i++, m>>=1) {
		if (m & 0x1)
			pfm_regmask_set(counters, i);
	}
}

static void
pfm_ita2_get_impl_pmcs(pfmlib_regmask_t *impl_pmcs)
{
	unsigned int i = 0;

	/* all pmcs are contiguous */
	for(i=0; i < PMU_ITA2_NUM_PMCS; i++)
		pfm_regmask_set(impl_pmcs, i);
}

static void
pfm_ita2_get_impl_pmds(pfmlib_regmask_t *impl_pmds)
{
	unsigned int i = 0;

	/* all pmds are contiguous */
	for(i=0; i < PMU_ITA2_NUM_PMDS; i++)
		pfm_regmask_set(impl_pmds, i);
}

static void
pfm_ita2_get_impl_counters(pfmlib_regmask_t *impl_counters)
{
	unsigned int i = 0;

	/* counting pmds are contiguous */
	for(i=4; i < 8; i++)
		pfm_regmask_set(impl_counters, i);
}

static void
pfm_ita2_get_hw_counter_width(unsigned int *width)
{
	*width = PMU_ITA2_COUNTER_WIDTH;
}

static int
pfm_ita2_get_event_description(unsigned int ev, char **str)
{
	char *s;
	s = itanium2_pe[ev].pme_desc;
	if (s) {
		*str = strdup(s);
	} else {
		*str = NULL;
	}
	return PFMLIB_SUCCESS;
}

static int
pfm_ita2_get_cycle_event(pfmlib_event_t *e)
{
	e->event = PME_ITA2_CPU_CYCLES;
	return PFMLIB_SUCCESS;

}

static int
pfm_ita2_get_inst_retired(pfmlib_event_t *e)
{
	e->event = PME_ITA2_IA64_INST_RETIRED;
	return PFMLIB_SUCCESS;
}

pfm_pmu_support_t itanium2_support={
	.pmu_name		= "itanium2",
	.pmu_type		= PFMLIB_ITANIUM2_PMU,
	.pme_count		= PME_ITA2_EVENT_COUNT,
	.pmc_count		= PMU_ITA2_NUM_PMCS,
	.pmd_count		= PMU_ITA2_NUM_PMDS,
	.num_cnt		= PMU_ITA2_NUM_COUNTERS,
	.get_event_code		= pfm_ita2_get_event_code,
	.get_event_name		= pfm_ita2_get_event_name,
	.get_event_counters	= pfm_ita2_get_event_counters,
	.dispatch_events	= pfm_ita2_dispatch_events,
	.pmu_detect		= pfm_ita2_detect,
	.get_impl_pmcs		= pfm_ita2_get_impl_pmcs,
	.get_impl_pmds		= pfm_ita2_get_impl_pmds,
	.get_impl_counters	= pfm_ita2_get_impl_counters,
	.get_hw_counter_width	= pfm_ita2_get_hw_counter_width,
	.get_event_desc         = pfm_ita2_get_event_description,
	.get_cycle_event	= pfm_ita2_get_cycle_event,
	.get_inst_retired_event = pfm_ita2_get_inst_retired
};
