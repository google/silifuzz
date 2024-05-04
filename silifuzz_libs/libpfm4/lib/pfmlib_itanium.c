/*
 * pfmlib_itanium.c : support for Itanium-family PMU
 *
 * Copyright (c) 2001-2006 Hewlett-Packard Development Company, L.P.
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
#include <perfmon/pfmlib_itanium.h>

/* private headers */
#include "pfmlib_priv.h"		/* library private */
#include "pfmlib_priv_ia64.h"		/* architecture private */
#include "pfmlib_itanium_priv.h"	/* PMU private */
#include "itanium_events.h"		/* PMU private */

#define is_ear(i)	event_is_ear(itanium_pe+(i))
#define is_ear_tlb(i)	event_is_tlb_ear(itanium_pe+(i))
#define is_iear(i)	event_is_iear(itanium_pe+(i))
#define is_dear(i)	event_is_dear(itanium_pe+(i))
#define is_btb(i)	event_is_btb(itanium_pe+(i))
#define has_opcm(i)	event_opcm_ok(itanium_pe+(i))
#define has_iarr(i)	event_iarr_ok(itanium_pe+(i))
#define has_darr(i)	event_darr_ok(itanium_pe+(i))

#define evt_use_opcm(e)		((e)->pfp_ita_pmc8.opcm_used != 0 || (e)->pfp_ita_pmc9.opcm_used !=0)
#define evt_use_irange(e)	((e)->pfp_ita_irange.rr_used)
#define evt_use_drange(e)	((e)->pfp_ita_drange.rr_used)

#define evt_umask(e)		itanium_pe[(e)].pme_umask

/* let's define some handy shortcuts! */
#define pmc_plm		pmc_ita_count_reg.pmc_plm
#define pmc_ev		pmc_ita_count_reg.pmc_ev
#define pmc_oi		pmc_ita_count_reg.pmc_oi
#define pmc_pm		pmc_ita_count_reg.pmc_pm
#define pmc_es		pmc_ita_count_reg.pmc_es
#define pmc_umask	pmc_ita_count_reg.pmc_umask
#define pmc_thres	pmc_ita_count_reg.pmc_thres
#define pmc_ism		pmc_ita_count_reg.pmc_ism

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
#define PFMLIB_ITA_PMC_BASE 0


static int
pfm_ita_detect(void)
{
	int ret = PFMLIB_ERR_NOTSUPP;

	/*
	 * we support all chips (there is only one!) in the Itanium family
	 */
	if (pfm_ia64_get_cpu_family() == 0x07) ret = PFMLIB_SUCCESS;
	return ret;
}

/*
 * Part of the following code will eventually go into a perfmon library
 */
static int
valid_assign(unsigned int *as, pfmlib_regmask_t *r_pmcs, unsigned int cnt)
{
	unsigned int i;
	for(i=0; i < cnt; i++) {
		if (as[i]==0) return PFMLIB_ERR_NOASSIGN;
		/*
		 * take care of restricted PMC registers
		 */
		if (pfm_regmask_isset(r_pmcs, as[i]))
			return PFMLIB_ERR_NOASSIGN;
	}
	return PFMLIB_SUCCESS;
}

/*
 * Automatically dispatch events to corresponding counters following constraints.
 */
static int
pfm_ita_dispatch_counters(pfmlib_input_param_t *inp, pfmlib_ita_input_param_t *mod_in, pfmlib_output_param_t *outp)
{
#define	has_counter(e,b)	(itanium_pe[e].pme_counters & (1 << (b)) ? (b) : 0)
	pfmlib_ita_input_param_t *param = mod_in;
	pfm_ita_pmc_reg_t reg;
	pfmlib_event_t *e;
	pfmlib_reg_t *pc, *pd;
	pfmlib_regmask_t *r_pmcs;
	unsigned int i,j,k,l, m;
	unsigned int max_l0, max_l1, max_l2, max_l3;
	unsigned int assign[PMU_ITA_NUM_COUNTERS];
	unsigned int cnt;

	e      = inp->pfp_events;
	pc     = outp->pfp_pmcs;
	pd     = outp->pfp_pmds;
	cnt    = inp->pfp_event_count;
	r_pmcs = &inp->pfp_unavail_pmcs;

	if (PFMLIB_DEBUG()) {
		for (m=0; m < cnt; m++) {
			DPRINT("ev[%d]=%s counters=0x%lx\n", m, itanium_pe[e[m].event].pme_name,
				itanium_pe[e[m].event].pme_counters);
		}
	}
	if (cnt > PMU_ITA_NUM_COUNTERS) return PFMLIB_ERR_TOOMANY;

	max_l0 = PMU_ITA_FIRST_COUNTER + PMU_ITA_NUM_COUNTERS;
	max_l1 = PMU_ITA_FIRST_COUNTER + PMU_ITA_NUM_COUNTERS*(cnt>1);
	max_l2 = PMU_ITA_FIRST_COUNTER + PMU_ITA_NUM_COUNTERS*(cnt>2);
	max_l3 = PMU_ITA_FIRST_COUNTER + PMU_ITA_NUM_COUNTERS*(cnt>3);

	DPRINT("max_l0=%u max_l1=%u max_l2=%u max_l3=%u\n", max_l0, max_l1, max_l2, max_l3);
	/*
	 *  This code needs fixing. It is not very pretty and
	 *  won't handle more than 4 counters if more become
	 *  available !
	 *  For now, worst case in the loop nest: 4! (factorial)
	 */
	for (i=PMU_ITA_FIRST_COUNTER; i < max_l0; i++) {

		assign[0]= has_counter(e[0].event,i);

		if (max_l1 == PMU_ITA_FIRST_COUNTER && valid_assign(assign, r_pmcs, cnt) == PFMLIB_SUCCESS) goto done;

		for (j=PMU_ITA_FIRST_COUNTER; j < max_l1; j++) {

			if (j == i) continue;

			assign[1] = has_counter(e[1].event,j);

			if (max_l2 == PMU_ITA_FIRST_COUNTER && valid_assign(assign, r_pmcs, cnt) == PFMLIB_SUCCESS) goto done;

			for (k=PMU_ITA_FIRST_COUNTER; k < max_l2; k++) {

				if(k == i || k == j) continue;

				assign[2] = has_counter(e[2].event,k);

				if (max_l3 == PMU_ITA_FIRST_COUNTER && valid_assign(assign, r_pmcs, cnt) == PFMLIB_SUCCESS) goto done;
				for (l=PMU_ITA_FIRST_COUNTER; l < max_l3; l++) {

					if(l == i || l == j || l == k) continue;

					assign[3] = has_counter(e[3].event,l);

					if (valid_assign(assign, r_pmcs, cnt) == PFMLIB_SUCCESS) goto done;
				}
			}
		}
	}
	/* we cannot satisfy the constraints */
	return PFMLIB_ERR_NOASSIGN;
done:
	for (j=0; j < cnt ; j++ ) {
		reg.pmc_val = 0; /* clear all */
		/* if plm is 0, then assume not specified per-event and use default */
		reg.pmc_plm    = e[j].plm ? e[j].plm : inp->pfp_dfl_plm;
		reg.pmc_oi     = 1; /* overflow interrupt */
		reg.pmc_pm     = inp->pfp_flags & PFMLIB_PFP_SYSTEMWIDE ? 1 : 0;
		reg.pmc_thres  = param ? param->pfp_ita_counters[j].thres: 0;
		reg.pmc_ism    = param ? param->pfp_ita_counters[j].ism : PFMLIB_ITA_ISM_BOTH;
		reg.pmc_umask  = is_ear(e[j].event) ? 0x0 : evt_umask(e[j].event);
		reg.pmc_es     = itanium_pe[e[j].event].pme_code;

		pc[j].reg_num     = assign[j];
		pc[j].reg_value   = reg.pmc_val;
		pc[j].reg_addr    = assign[j];
		pc[j].reg_alt_addr= assign[j];

		pd[j].reg_num = assign[j];
		pd[j].reg_addr = assign[j];
		pd[j].reg_alt_addr = assign[j];

		__pfm_vbprintf("[PMC%u(pmc%u)=0x%06lx thres=%d es=0x%02x plm=%d umask=0x%x pm=%d ism=0x%x oi=%d] %s\n",
				assign[j],
				assign[j],
				reg.pmc_val,
				reg.pmc_thres,
				reg.pmc_es,reg.pmc_plm,
				reg.pmc_umask, reg.pmc_pm,
				reg.pmc_ism,
				reg.pmc_oi,
				itanium_pe[e[j].event].pme_name);
		__pfm_vbprintf("[PMD%u(pmd%u)]\n", pd[j].reg_num, pd[j].reg_num);
	}
	/* number of PMC registers programmed */
	outp->pfp_pmc_count = cnt;
	outp->pfp_pmd_count = cnt;

	return PFMLIB_SUCCESS;
}

static int
pfm_dispatch_iear(pfmlib_input_param_t *inp, pfmlib_ita_input_param_t *mod_in, pfmlib_output_param_t *outp)
{
	pfm_ita_pmc_reg_t reg;
	pfmlib_ita_input_param_t *param = mod_in;
	pfmlib_ita_input_param_t fake_param;
	pfmlib_reg_t *pc, *pd;
	unsigned int pos1, pos2;
	int iear_idx = -1;
	unsigned int i, count;

	pc = outp->pfp_pmcs;
	pd = outp->pfp_pmds;
	pos1 = outp->pfp_pmc_count;
	pos2 = outp->pfp_pmd_count;
	count = inp->pfp_event_count;

	for (i=0; i < count; i++) {
		if (is_iear(inp->pfp_events[i].event)) iear_idx = i;
	}

	if (param == NULL || mod_in->pfp_ita_iear.ear_used == 0) {

		/*
		 * case 3: no I-EAR event, no (or nothing) in param->pfp_ita2_iear.ear_used
		 */
		if (iear_idx == -1) return PFMLIB_SUCCESS;

		memset(&fake_param, 0, sizeof(fake_param));
		param = &fake_param;

		pfm_ita_get_ear_mode(inp->pfp_events[iear_idx].event, &param->pfp_ita_iear.ear_mode);

		param->pfp_ita_iear.ear_umask = evt_umask(inp->pfp_events[iear_idx].event);
		param->pfp_ita_iear.ear_ism   = PFMLIB_ITA_ISM_BOTH; /* force both instruction sets */

		DPRINT("I-EAR event with no info\n");
	}

	/* sanity check on the mode */
	if (param->pfp_ita_iear.ear_mode < 0 || param->pfp_ita_iear.ear_mode > 2) return PFMLIB_ERR_INVAL;

	/*
	 * case 2: ear_used=1, event is defined, we use the param info as it is more precise
	 * case 4: ear_used=1, no event (free running I-EAR), use param info
	 */
	reg.pmc_val = 0;

	/* if plm is 0, then assume not specified per-event and use default */
	reg.pmc10_ita_reg.iear_plm   = param->pfp_ita_iear.ear_plm ? param->pfp_ita_iear.ear_plm : inp->pfp_dfl_plm;
	reg.pmc10_ita_reg.iear_pm    = inp->pfp_flags & PFMLIB_PFP_SYSTEMWIDE ? 1 : 0;
	reg.pmc10_ita_reg.iear_tlb   = param->pfp_ita_iear.ear_mode;
	reg.pmc10_ita_reg.iear_umask = param->pfp_ita_iear.ear_umask;
	reg.pmc10_ita_reg.iear_ism   = param->pfp_ita_iear.ear_ism;

	if (pfm_regmask_isset(&inp->pfp_unavail_pmcs, 10))
		return PFMLIB_ERR_NOASSIGN;

	pc[pos1].reg_num     = 10;  /* PMC10 is I-EAR config register */
	pc[pos1].reg_value   = reg.pmc_val;
	pc[pos1].reg_addr    = 10;
	pc[pos1].reg_alt_addr= 10;
	pos1++;
	pd[pos2].reg_num     = 0; 
	pd[pos2].reg_addr    = 0;
	pd[pos2].reg_alt_addr  = 0;
	pos2++;
	pd[pos2].reg_num     = 1; 
	pd[pos2].reg_addr    = 1;
	pd[pos2].reg_alt_addr  = 1;
	pos2++;

	__pfm_vbprintf("[PMC10(pmc10)=0x%lx tlb=%s plm=%d pm=%d ism=0x%x umask=0x%x]\n",
			reg.pmc_val,
			reg.pmc10_ita_reg.iear_tlb ? "Yes" : "No",
			reg.pmc10_ita_reg.iear_plm,
			reg.pmc10_ita_reg.iear_pm,
			reg.pmc10_ita_reg.iear_ism,
			reg.pmc10_ita_reg.iear_umask);
	__pfm_vbprintf("[PMD0(pmd0)]\n[PMD1(pmd1)\n");

	/* update final number of entries used */
	outp->pfp_pmc_count = pos1;
	outp->pfp_pmd_count = pos2;

	return PFMLIB_SUCCESS;
}

static int
pfm_dispatch_dear(pfmlib_input_param_t *inp, pfmlib_ita_input_param_t *mod_in, pfmlib_output_param_t *outp)
{
	pfm_ita_pmc_reg_t reg;
	pfmlib_ita_input_param_t *param = mod_in;
	pfmlib_ita_input_param_t fake_param;
	pfmlib_reg_t *pc, *pd;
	unsigned int pos1, pos2;
	int dear_idx = -1;
	unsigned int i, count;

	pc = outp->pfp_pmcs;
	pd = outp->pfp_pmds;
	pos1 = outp->pfp_pmc_count;
	pos2 = outp->pfp_pmd_count;
	count = inp->pfp_event_count;

	for (i=0; i < count; i++) {
		if (is_dear(inp->pfp_events[i].event)) dear_idx = i;
	}

	if (param == NULL || param->pfp_ita_dear.ear_used == 0) {

		/*
		 * case 3: no D-EAR event, no (or nothing) in param->pfp_ita2_dear.ear_used
		 */
		if (dear_idx == -1) return PFMLIB_SUCCESS;

		memset(&fake_param, 0, sizeof(fake_param));
		param = &fake_param;

		pfm_ita_get_ear_mode(inp->pfp_events[dear_idx].event, &param->pfp_ita_dear.ear_mode);

		param->pfp_ita_dear.ear_umask = evt_umask(inp->pfp_events[dear_idx].event);
		param->pfp_ita_dear.ear_ism   = PFMLIB_ITA_ISM_BOTH; /* force both instruction sets */

		DPRINT("D-EAR event with no info\n");
	}


	/* sanity check on the mode */
	if (param->pfp_ita_dear.ear_mode > 2) return PFMLIB_ERR_INVAL;

	/*
	 * case 2: ear_used=1, event is defined, we use the param info as it is more precise
	 * case 4: ear_used=1, no event (free running D-EAR), use param info
	 */
	reg.pmc_val = 0;

	/* if plm is 0, then assume not specified per-event and use default */
	reg.pmc11_ita_reg.dear_plm   = param->pfp_ita_dear.ear_plm ? param->pfp_ita_dear.ear_plm : inp->pfp_dfl_plm;
	reg.pmc11_ita_reg.dear_pm    = inp->pfp_flags & PFMLIB_PFP_SYSTEMWIDE ? 1 : 0;
	reg.pmc11_ita_reg.dear_tlb   = param->pfp_ita_dear.ear_mode;
	reg.pmc11_ita_reg.dear_ism   = param->pfp_ita_dear.ear_ism;
	reg.pmc11_ita_reg.dear_umask = param->pfp_ita_dear.ear_umask;
	reg.pmc11_ita_reg.dear_pt    = param->pfp_ita_drange.rr_used ? 0: 1;

	if (pfm_regmask_isset(&inp->pfp_unavail_pmcs, 11))
		return PFMLIB_ERR_NOASSIGN;

	pc[pos1].reg_num     = 11;  /* PMC11 is D-EAR config register */
	pc[pos1].reg_value   = reg.pmc_val;
	pc[pos1].reg_addr    = 11;
	pos1++;
	pd[pos2].reg_num     = 2; 
	pd[pos2].reg_addr    = 2;
	pd[pos2].reg_alt_addr  = 2;
	pos2++;
	pd[pos2].reg_num     = 3; 
	pd[pos2].reg_addr    = 3;
	pd[pos2].reg_alt_addr  = 3;
	pos2++;
	pd[pos2].reg_num     = 17; 
	pd[pos2].reg_addr    = 17;
	pd[pos2].reg_alt_addr  = 17;
	pos2++;

	__pfm_vbprintf("[PMC11(pmc11)=0x%lx tlb=%s plm=%d pm=%d ism=0x%x umask=0x%x pt=%d]\n",
			reg.pmc_val,
			reg.pmc11_ita_reg.dear_tlb ? "Yes" : "No",
			reg.pmc11_ita_reg.dear_plm,	
			reg.pmc11_ita_reg.dear_pm,
			reg.pmc11_ita_reg.dear_ism,
			reg.pmc11_ita_reg.dear_umask,
			reg.pmc11_ita_reg.dear_pt);
	__pfm_vbprintf("[PMD2(pmd2)]\n[PMD3(pmd3)\nPMD17(pmd17)\n");

	/* update final number of entries used */
	outp->pfp_pmc_count = pos1;
	outp->pfp_pmd_count = pos2;

	return PFMLIB_SUCCESS;
}

static int
pfm_dispatch_opcm(pfmlib_input_param_t *inp, pfmlib_ita_input_param_t *mod_in, pfmlib_output_param_t *outp)
{
	pfmlib_ita_input_param_t *param = mod_in;
	pfm_ita_pmc_reg_t reg;
	pfmlib_reg_t *pc = outp->pfp_pmcs;
	int pos = outp->pfp_pmc_count;

	if (param == NULL) return PFMLIB_SUCCESS;

	if (param->pfp_ita_pmc8.opcm_used) {

		reg.pmc_val = param->pfp_ita_pmc8.pmc_val;

		if (pfm_regmask_isset(&inp->pfp_unavail_pmcs, 8))
			return PFMLIB_ERR_NOASSIGN;

		pc[pos].reg_num     = 8;
		pc[pos].reg_value   = reg.pmc_val;
		pc[pos].reg_addr  = 8;
		pc[pos].reg_alt_addr  = 8;
		pos++;


		__pfm_vbprintf("[PMC8(pmc8)=0x%lx m=%d i=%d f=%d b=%d match=0x%x mask=0x%x]\n",
				reg.pmc_val,
				reg.pmc8_9_ita_reg.m,
				reg.pmc8_9_ita_reg.i,
				reg.pmc8_9_ita_reg.f,
				reg.pmc8_9_ita_reg.b,
				reg.pmc8_9_ita_reg.match,
				reg.pmc8_9_ita_reg.mask);
	}

	if (param->pfp_ita_pmc9.opcm_used) {

		reg.pmc_val = param->pfp_ita_pmc9.pmc_val;

		if (pfm_regmask_isset(&inp->pfp_unavail_pmcs, 9))
			return PFMLIB_ERR_NOASSIGN;

		pc[pos].reg_num     = 9;
		pc[pos].reg_value   = reg.pmc_val;
		pc[pos].reg_addr  = 9;
		pc[pos].reg_alt_addr  = 9;
		pos++;


		__pfm_vbprintf("[PMC9(pmc9)=0x%lx m=%d i=%d f=%d b=%d match=0x%x mask=0x%x]\n",
				reg.pmc_val,
				reg.pmc8_9_ita_reg.m,
				reg.pmc8_9_ita_reg.i,
				reg.pmc8_9_ita_reg.f,
				reg.pmc8_9_ita_reg.b,
				reg.pmc8_9_ita_reg.match,
				reg.pmc8_9_ita_reg.mask);
	}
	outp->pfp_pmc_count = pos;
	return PFMLIB_SUCCESS;
}


static int
pfm_dispatch_btb(pfmlib_input_param_t *inp, pfmlib_ita_input_param_t *mod_in, pfmlib_output_param_t *outp)
{
	pfm_ita_pmc_reg_t reg;
	pfmlib_ita_input_param_t *param = mod_in;
	pfmlib_ita_input_param_t fake_param;
	pfmlib_reg_t *pc, *pd;
	int found_btb=0;
	unsigned int i, count;
	unsigned int  pos1, pos2;

	reg.pmc_val = 0;

	pc = outp->pfp_pmcs;
	pd = outp->pfp_pmds;
	pos1 = outp->pfp_pmc_count;
	pos2 = outp->pfp_pmd_count;

	count = inp->pfp_event_count;
	for (i=0; i < count; i++) {
		if (is_btb(inp->pfp_events[i].event)) found_btb = 1;
	}

	if (param == NULL || param->pfp_ita_btb.btb_used == 0) {

		/*
		 * case 3: no BTB event, no param
		 */
		if (found_btb  == 0) return PFMLIB_SUCCESS;

		/*
		 * case 1: BTB event, no param, capture all branches
		 */
		memset(&fake_param, 0, sizeof(fake_param));
		param = &fake_param;

		param->pfp_ita_btb.btb_tar = 0x1; 	/* capture TAR  */
		param->pfp_ita_btb.btb_tm  = 0x3; 	/* all branches */
		param->pfp_ita_btb.btb_ptm = 0x3; 	/* all branches */
		param->pfp_ita_btb.btb_ppm = 0x3; 	/* all branches */
		param->pfp_ita_btb.btb_tac = 0x1; 	/* capture TAC  */
		param->pfp_ita_btb.btb_bac = 0x1; 	/* capture BAC  */

		DPRINT("BTB event with no info\n");
	}

	/*
	 * case 2: BTB event, param
	 * case 4: no BTB event, param (free running mode)
	 */

	/* if plm is 0, then assume not specified per-event and use default */
	reg.pmc12_ita_reg.btbc_plm = param->pfp_ita_btb.btb_plm ? param->pfp_ita_btb.btb_plm : inp->pfp_dfl_plm;
	reg.pmc12_ita_reg.btbc_pm  = inp->pfp_flags & PFMLIB_PFP_SYSTEMWIDE ? 1 : 0;
	reg.pmc12_ita_reg.btbc_tar = param->pfp_ita_btb.btb_tar & 0x1;
	reg.pmc12_ita_reg.btbc_tm  = param->pfp_ita_btb.btb_tm  & 0x3;
	reg.pmc12_ita_reg.btbc_ptm = param->pfp_ita_btb.btb_ptm & 0x3;
	reg.pmc12_ita_reg.btbc_ppm = param->pfp_ita_btb.btb_ppm & 0x3;
	reg.pmc12_ita_reg.btbc_bpt = param->pfp_ita_btb.btb_tac & 0x1;
	reg.pmc12_ita_reg.btbc_bac = param->pfp_ita_btb.btb_bac & 0x1;

	if (pfm_regmask_isset(&inp->pfp_unavail_pmcs, 12))
		return PFMLIB_ERR_NOASSIGN;

	pc[pos1].reg_num   = 12;
	pc[pos1].reg_value = reg.pmc_val;
	pc[pos1].reg_value = 12;
	pos1++;

	__pfm_vbprintf("[PMC12(pmc12)=0x%lx plm=%d pm=%d tar=%d tm=%d ptm=%d ppm=%d bpt=%d bac=%d]\n",
			reg.pmc_val,
			reg.pmc12_ita_reg.btbc_plm,
			reg.pmc12_ita_reg.btbc_pm,
			reg.pmc12_ita_reg.btbc_tar,
			reg.pmc12_ita_reg.btbc_tm,
			reg.pmc12_ita_reg.btbc_ptm,
			reg.pmc12_ita_reg.btbc_ppm,
			reg.pmc12_ita_reg.btbc_bpt,
			reg.pmc12_ita_reg.btbc_bac);

	/*
	 * PMD16 is included in list of used PMD
	 */
	for(i=8; i < 17; i++, pos2++) {
		pd[pos2].reg_num = i;
		pd[pos2].reg_addr = i;
		pd[pos2].reg_alt_addr = i;
		__pfm_vbprintf("[PMD%u(pmd%u)]\n", pd[pos2].reg_num, pd[pos2].reg_num);
	}

	/* update final number of entries used */
	outp->pfp_pmc_count = pos1;
	outp->pfp_pmd_count = pos2;

	return PFMLIB_SUCCESS;
}

/*
 * mode = 0 -> check code (enforce bundle alignment)
 * mode = 1 -> check data
 */
static int
check_intervals(pfmlib_ita_input_rr_t *irr, int mode, int *n_intervals)
{
	int i;
	pfmlib_ita_input_rr_desc_t *lim = irr->rr_limits;

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

	DPRINT("largest chunk: 2^%d=0x%lx @0x%016lx-0x%016lx\n", p2, 1UL<<p2, l_addr, l_addr+(1UL<<p2));
	if (l_size) DPRINT("before: 0x%016lx-0x%016lx\n", start, l_addr);
	if (r_size) DPRINT("after : 0x%016lx-0x%016lx\n", l_addr+(1UL<<p2), end);

	if (dir == 0 && l_size != 0 && nbr == 1) {
		p2++;
		l_addr = end - (1UL << p2);
		if (PFMLIB_DEBUG()) {
			l_offs = start - l_addr;
			DPRINT(">>l_offs: 0x%lx\n", l_offs);
		}
	} else if (dir == 1 && r_size != 0 && nbr == 1) {
		p2++;
		l_addr = start;
		if (PFMLIB_DEBUG()) {
			r_offs = l_addr+(1UL<<p2) - end;
			DPRINT(">>r_offs: 0x%lx\n", r_offs);
		}
	}
	l_size = l_addr - start;
	r_size = end - l_addr-(1UL<<p2);
	
	DPRINT(">>largest chunk: 2^%d @0x%016lx-0x%016lx\n", p2, l_addr, l_addr+(1UL<<p2));
	if (l_size && !l_offs) DPRINT(">>before: 0x%016lx-0x%016lx\n", start, l_addr);
	if (r_size && !r_offs) DPRINT(">>after : 0x%016lx-0x%016lx\n", l_addr+(1UL<<p2), end);

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
	br[*idx].reg_addr    = *reg_idx;
	br[*idx].reg_alt_addr= *reg_idx;

	br[*idx+1].reg_num   = *reg_idx+1;
	br[*idx+1].reg_value = db.val;
	br[*idx+1].reg_addr  = *reg_idx+1;
	br[*idx+1].reg_alt_addr = *reg_idx+1;

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
print_one_range(pfmlib_ita_input_rr_desc_t *in_rr, pfmlib_ita_output_rr_desc_t *out_rr, pfmlib_reg_t *dbr, int base_idx, int n_pairs)
{
	int j;
	dbreg_t d;
	unsigned long r_end;

	__pfm_vbprintf("[0x%lx-0x%lx): %d register pair(s)\n", in_rr->rr_start, in_rr->rr_end, n_pairs);
	__pfm_vbprintf("start offset: -0x%lx end_offset: +0x%lx\n", out_rr->rr_soff, out_rr->rr_eoff);

	for (j=0; j < n_pairs; j++, base_idx += 2) {

		d.val = dbr[base_idx+1].reg_value;
		r_end = dbr[base_idx].reg_value+((~(d.db.db_mask)) & ~(0xffUL << 56));

		__pfm_vbprintf("brp%u:  db%u: 0x%016lx db%u: plm=0x%x mask=0x%016lx end=0x%016lx\n",
			dbr[base_idx].reg_num>>1,
			dbr[base_idx].reg_num,
			dbr[base_idx].reg_value,
			dbr[base_idx+1].reg_num,
			d.db.db_plm,
			(unsigned long) d.db.db_mask,
			r_end);
	}
}

static int
compute_normal_rr(pfmlib_ita_input_rr_t *irr, int dfl_plm, int n, int *base_idx, pfmlib_ita_output_rr_t *orr)
{
	pfmlib_ita_input_rr_desc_t *in_rr;
	pfmlib_ita_output_rr_desc_t *out_rr;
	unsigned long r_end;
	pfmlib_reg_t *br;
	dbreg_t d;
	int i, j, br_index, reg_idx, prev_index;

	in_rr     = irr->rr_limits;
	out_rr    = orr->rr_infos;
	br        = orr->rr_br;
	reg_idx   = *base_idx;
	br_index  = 0;

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

		if (PFMLIB_VERBOSE()) print_one_range(in_rr, out_rr, br, prev_index, (br_index-prev_index)>>1);


	}

	/* do not have enough registers to cover all the ranges */
	if (br_index == 8 && i < n) return PFMLIB_ERR_TOOMANY;

	orr->rr_nbr_used = br_index;

	return PFMLIB_SUCCESS;
}


static int
pfm_dispatch_irange(pfmlib_input_param_t *inp, pfmlib_ita_input_param_t *mod_in, pfmlib_output_param_t *outp, pfmlib_ita_output_param_t *mod_out)
{
	pfm_ita_pmc_reg_t reg;
	pfmlib_ita_input_param_t *param = mod_in;
	pfmlib_reg_t *pc = outp->pfp_pmcs;
	pfmlib_ita_input_rr_t *irr;
	pfmlib_ita_output_rr_t *orr;
	int pos = outp->pfp_pmc_count;
	int ret, base_idx = 0;
	int n_intervals;

	if (param == NULL || param->pfp_ita_irange.rr_used == 0) return PFMLIB_SUCCESS;

	if (mod_out == NULL) return PFMLIB_ERR_INVAL;

	irr = &param->pfp_ita_irange;
	orr = &mod_out->pfp_ita_irange;

	ret = check_intervals(irr, 0, &n_intervals);
	if (ret != PFMLIB_SUCCESS) return ret;

	if (n_intervals < 1) return PFMLIB_ERR_IRRINVAL;
	
	DPRINT("n_intervals=%d\n", n_intervals);

	ret = compute_normal_rr(irr, inp->pfp_dfl_plm, n_intervals, &base_idx, orr);
	if (ret != PFMLIB_SUCCESS) {
		return ret == PFMLIB_ERR_TOOMANY ? PFMLIB_ERR_IRRTOOMANY : ret;
	}
	reg.pmc_val = 0;

	reg.pmc13_ita_reg.irange_ta = 0x0;

	if (pfm_regmask_isset(&inp->pfp_unavail_pmcs, 13))
		return PFMLIB_ERR_NOASSIGN;

	pc[pos].reg_num     = 13;
	pc[pos].reg_value   = reg.pmc_val;
	pc[pos].reg_addr    = 13;
	pc[pos].reg_alt_addr= 13;
	pos++;

	__pfm_vbprintf("[PMC13(pmc13)=0x%lx ta=%d]\n", reg.pmc_val, reg.pmc13_ita_reg.irange_ta);
	
	outp->pfp_pmc_count = pos;

	return PFMLIB_SUCCESS;
}
	
static int
pfm_dispatch_drange(pfmlib_input_param_t *inp, pfmlib_ita_input_param_t *mod_in, pfmlib_output_param_t *outp, pfmlib_ita_output_param_t *mod_out)
{
	pfmlib_ita_input_param_t *param = mod_in;
	pfmlib_event_t *e = inp->pfp_events;
	pfmlib_reg_t *pc = outp->pfp_pmcs;
	pfmlib_ita_input_rr_t *irr;
	pfmlib_ita_output_rr_t *orr;
	pfm_ita_pmc_reg_t reg;
	unsigned int i, count;
	int pos = outp->pfp_pmc_count;
	int ret, base_idx = 0;
	int n_intervals;

	if (param == NULL || param->pfp_ita_drange.rr_used == 0) return PFMLIB_SUCCESS;

	if (mod_out == NULL) return PFMLIB_ERR_INVAL;

	irr = &param->pfp_ita_drange;
	orr = &mod_out->pfp_ita_drange;

	ret = check_intervals(irr, 1 , &n_intervals);
	if (ret != PFMLIB_SUCCESS) return ret;

	if (n_intervals < 1) return PFMLIB_ERR_DRRINVAL;
	
	DPRINT("n_intervals=%d\n", n_intervals);

	ret = compute_normal_rr(irr, inp->pfp_dfl_plm, n_intervals, &base_idx, orr);
	if (ret != PFMLIB_SUCCESS) {
		return ret == PFMLIB_ERR_TOOMANY ? PFMLIB_ERR_DRRTOOMANY : ret;
	}
	count = inp->pfp_event_count;
	for (i=0; i < count; i++) {
		if (is_dear(e[i].event)) return PFMLIB_SUCCESS; /* will be done there */
	}

	reg.pmc_val = 0UL;
	/*
	 * here we have no other choice but to use the default priv level as there is no
	 * specific D-EAR event provided
	 */
	reg.pmc11_ita_reg.dear_plm = inp->pfp_dfl_plm;

	if (pfm_regmask_isset(&inp->pfp_unavail_pmcs, 11))
		return PFMLIB_ERR_NOASSIGN;

	pc[pos].reg_num     = 11;
	pc[pos].reg_value   = reg.pmc_val;
	pc[pos].reg_addr    = 11;
	pc[pos].reg_alt_addr= 11;
	pos++;

	__pfm_vbprintf("[PMC11(pmc11)=0x%lx tlb=%s plm=%d pm=%d ism=0x%x umask=0x%x pt=%d]\n",
			reg.pmc_val,
			reg.pmc11_ita_reg.dear_tlb ? "Yes" : "No",
			reg.pmc11_ita_reg.dear_plm,	
			reg.pmc11_ita_reg.dear_pm,
			reg.pmc11_ita_reg.dear_ism,
			reg.pmc11_ita_reg.dear_umask,
			reg.pmc11_ita_reg.dear_pt);


	outp->pfp_pmc_count = pos;

	return PFMLIB_SUCCESS;
}

static int
check_qualifier_constraints(pfmlib_input_param_t *inp, pfmlib_ita_input_param_t *mod_in)
{
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
		if (mod_in->pfp_ita_counters[i].flags & PFMLIB_ITA_FL_EVT_NO_QUALCHECK) continue;

		if (evt_use_irange(mod_in) && has_iarr(e[i].event) == 0) return PFMLIB_ERR_FEATCOMB;
		if (evt_use_drange(mod_in) && has_darr(e[i].event) == 0) return PFMLIB_ERR_FEATCOMB;
		if (evt_use_opcm(mod_in) && has_opcm(e[i].event) == 0) return PFMLIB_ERR_FEATCOMB;
	}
	return PFMLIB_SUCCESS;
}

static int
check_range_plm(pfmlib_input_param_t *inp, pfmlib_ita_input_param_t *mod_in)
{
	unsigned int i, count;

	if (mod_in->pfp_ita_drange.rr_used == 0 && mod_in->pfp_ita_irange.rr_used == 0) return PFMLIB_SUCCESS;

	/*
	 * range restriction applies to all events, therefore we must have a consistent
	 * set of plm and they must match the pfp_dfl_plm which is used to setup the debug
	 * registers
	 */
	count = inp->pfp_event_count;
	for(i=0; i < count; i++) {
		if (inp->pfp_events[i].plm  && inp->pfp_events[i].plm != inp->pfp_dfl_plm) return PFMLIB_ERR_FEATCOMB;
	}
	return PFMLIB_SUCCESS;
}

static int
pfm_ita_dispatch_events(pfmlib_input_param_t *inp, void *model_in, pfmlib_output_param_t *outp, void *model_out)
{
	int ret;
	pfmlib_ita_input_param_t *mod_in  = (pfmlib_ita_input_param_t *)model_in;
	pfmlib_ita_output_param_t *mod_out = (pfmlib_ita_output_param_t *)model_out;

	/*
	 * nothing will come out of this combination
	 */
	if (mod_out && mod_in == NULL) return PFMLIB_ERR_INVAL;

	/* check opcode match, range restriction qualifiers */
	if (mod_in && check_qualifier_constraints(inp, mod_in) != PFMLIB_SUCCESS) return PFMLIB_ERR_FEATCOMB;

	/* check for problems with raneg restriction and per-event plm */
	if (mod_in && check_range_plm(inp, mod_in) != PFMLIB_SUCCESS) return PFMLIB_ERR_FEATCOMB;

	ret = pfm_ita_dispatch_counters(inp, mod_in, outp);
	if (ret != PFMLIB_SUCCESS) return ret;

	/* now check for I-EAR */
	ret = pfm_dispatch_iear(inp, mod_in, outp);
	if (ret != PFMLIB_SUCCESS) return ret;

	/* now check for D-EAR */
	ret = pfm_dispatch_dear(inp, mod_in, outp);
	if (ret != PFMLIB_SUCCESS) return ret;

	/* now check for Opcode matchers */
	ret = pfm_dispatch_opcm(inp, mod_in, outp);
	if (ret != PFMLIB_SUCCESS) return ret;

	ret = pfm_dispatch_btb(inp, mod_in, outp);
	if (ret != PFMLIB_SUCCESS) return ret;

	ret = pfm_dispatch_irange(inp, mod_in, outp, mod_out);;
	if (ret != PFMLIB_SUCCESS) return ret;

	ret = pfm_dispatch_drange(inp, mod_in, outp, mod_out);;

	return ret;
}

/* XXX: return value is also error code */
int
pfm_ita_get_event_maxincr(unsigned int i, unsigned int *maxincr)
{
	if (i >= PME_ITA_EVENT_COUNT || maxincr == NULL) return PFMLIB_ERR_INVAL;
	*maxincr = itanium_pe[i].pme_maxincr;
	return PFMLIB_SUCCESS;
}

int
pfm_ita_is_ear(unsigned int i)
{
	return i >= PME_ITA_EVENT_COUNT || ! is_ear(i) ? 0 : 1;
}

int
pfm_ita_is_dear(unsigned int i)
{
	return i >= PME_ITA_EVENT_COUNT || ! is_dear(i) ? 0 : 1;
}

int
pfm_ita_is_dear_tlb(unsigned int i)
{
	return i >= PME_ITA_EVENT_COUNT || ! (is_dear(i) && is_ear_tlb(i)) ? 0 : 1;
}
	
int
pfm_ita_is_dear_cache(unsigned int i)
{
	return i >= PME_ITA_EVENT_COUNT || ! (is_dear(i) && !is_ear_tlb(i)) ? 0 : 1;
}
	
int
pfm_ita_is_iear(unsigned int i)
{
	return i >= PME_ITA_EVENT_COUNT || ! is_iear(i) ? 0 : 1;
}

int
pfm_ita_is_iear_tlb(unsigned int i)
{
	return i >= PME_ITA_EVENT_COUNT || ! (is_iear(i) && is_ear_tlb(i)) ? 0 : 1;
}
	
int
pfm_ita_is_iear_cache(unsigned int i)
{
	return i >= PME_ITA_EVENT_COUNT || ! (is_iear(i) && !is_ear_tlb(i)) ? 0 : 1;
}
	
int
pfm_ita_is_btb(unsigned int i)
{
	return i >= PME_ITA_EVENT_COUNT || ! is_btb(i) ? 0 : 1;
}

int
pfm_ita_support_iarr(unsigned int i)
{
	return i >= PME_ITA_EVENT_COUNT || ! has_iarr(i) ? 0 : 1;
}


int
pfm_ita_support_darr(unsigned int i)
{
	return i >= PME_ITA_EVENT_COUNT || ! has_darr(i) ? 0 : 1;
}


int
pfm_ita_support_opcm(unsigned int i)
{
	return i >= PME_ITA_EVENT_COUNT || ! has_opcm(i) ? 0 : 1;
}

int
pfm_ita_get_ear_mode(unsigned int i, pfmlib_ita_ear_mode_t *m)
{
	if (!is_ear(i) || m == NULL) return PFMLIB_ERR_INVAL;

	*m = is_ear_tlb(i) ? PFMLIB_ITA_EAR_TLB_MODE : PFMLIB_ITA_EAR_CACHE_MODE;

	return PFMLIB_SUCCESS;
}


static int
pfm_ita_get_event_code(unsigned int i, unsigned int cnt, int *code)
{
	if (cnt != PFMLIB_CNT_FIRST && (cnt < 4 || cnt > 7))
		return PFMLIB_ERR_INVAL;

	*code = (int)itanium_pe[i].pme_code;

	return PFMLIB_SUCCESS;
}

/*
 * This function is accessible directly to the user
 */
int
pfm_ita_get_event_umask(unsigned int i, unsigned long *umask)
{
	if (i >= PME_ITA_EVENT_COUNT || umask == NULL) return PFMLIB_ERR_INVAL;
	*umask = evt_umask(i);
	return PFMLIB_SUCCESS;
}
	
static char *
pfm_ita_get_event_name(unsigned int i)
{
	return itanium_pe[i].pme_name;
}

static void
pfm_ita_get_event_counters(unsigned int j, pfmlib_regmask_t *counters)
{
	unsigned int i;
	unsigned long m;

	memset(counters, 0, sizeof(*counters));

	m =itanium_pe[j].pme_counters;
	for(i=0; m ; i++, m>>=1) {
		if (m & 0x1)
			pfm_regmask_set(counters, i);
	}
}

static void
pfm_ita_get_impl_pmcs(pfmlib_regmask_t *impl_pmcs)
{
	unsigned int i = 0;

	/* all pmcs are contiguous */
	for(i=0; i < PMU_ITA_NUM_PMCS; i++)
		pfm_regmask_set(impl_pmcs, i);
}

static void
pfm_ita_get_impl_pmds(pfmlib_regmask_t *impl_pmds)
{
	unsigned int i = 0;

	/* all pmds are contiguous */
	for(i=0; i < PMU_ITA_NUM_PMDS; i++)
		pfm_regmask_set(impl_pmds, i);
}

static void
pfm_ita_get_impl_counters(pfmlib_regmask_t *impl_counters)
{
	unsigned int i = 0;

	/* counting pmds are contiguous */
	for(i=4; i < 8; i++)
		pfm_regmask_set(impl_counters, i);
}
	
static void
pfm_ita_get_hw_counter_width(unsigned int *width)
{
	*width = PMU_ITA_COUNTER_WIDTH;
}

static int
pfm_ita_get_cycle_event(pfmlib_event_t *e)
{
	e->event = PME_ITA_CPU_CYCLES;
	return PFMLIB_SUCCESS;

}

static int
pfm_ita_get_inst_retired(pfmlib_event_t *e)
{
	e->event = PME_ITA_IA64_INST_RETIRED;
	return PFMLIB_SUCCESS;
}

pfm_pmu_support_t itanium_support={
	.pmu_name		= "itanium",
	.pmu_type		= PFMLIB_ITANIUM_PMU,
	.pme_count		= PME_ITA_EVENT_COUNT,
	.pmc_count		= PMU_ITA_NUM_PMCS,
	.pmd_count		= PMU_ITA_NUM_PMDS,
	.num_cnt		= PMU_ITA_NUM_COUNTERS,
	.get_event_code		= pfm_ita_get_event_code,
	.get_event_name		= pfm_ita_get_event_name,
	.get_event_counters	= pfm_ita_get_event_counters,
	.dispatch_events	= pfm_ita_dispatch_events,
	.pmu_detect		= pfm_ita_detect,
	.get_impl_pmcs		= pfm_ita_get_impl_pmcs,
	.get_impl_pmds		= pfm_ita_get_impl_pmds,
	.get_impl_counters	= pfm_ita_get_impl_counters,
	.get_hw_counter_width	= pfm_ita_get_hw_counter_width,
	.get_cycle_event	= pfm_ita_get_cycle_event,
	.get_inst_retired_event = pfm_ita_get_inst_retired
	/* no event description available for Itanium */
};
