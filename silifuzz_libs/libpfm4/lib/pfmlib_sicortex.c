/*
 * pfmlib_sicortex.c : support for the generic MIPS64 PMU family
 *
 * Contributed by Philip Mucci <mucci@cs.utk.edu> based on code from
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
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <malloc.h>

/* public headers */
#include <perfmon/pfmlib_gen_mips64.h>
#include <perfmon/pfmlib_sicortex.h>

/* private headers */
#include "pfmlib_priv.h"		/* library private */
#include "pfmlib_sicortex_priv.h"	/* architecture private */
#include "sicortex/ice9a/ice9a_all_spec_pme.h"
#include "sicortex/ice9b/ice9b_all_spec_pme.h"
#include "sicortex/ice9/ice9_scb_spec_sw.h"

/* let's define some handy shortcuts! */
#define sel_event_mask	perfsel.sel_event_mask
#define sel_exl		perfsel.sel_exl
#define sel_os		perfsel.sel_os
#define sel_usr		perfsel.sel_usr
#define sel_sup		perfsel.sel_sup
#define sel_int		perfsel.sel_int

static pme_sicortex_entry_t *sicortex_pe = NULL;

// CHANGE FOR ICET
#define core_counters 2

#define MAX_ICE9_PMCS 2+4+256
#define MAX_ICE9_PMDS 2+4+256

static int compute_ice9_counters(int type)
{
  int i;
  int bound = 0;
  pme_gen_mips64_entry_t *gen_mips64_pe = NULL;
  
  sicortex_support.pmd_count = 0;
  sicortex_support.pmc_count = 0;
  for (i=0;i<MAX_ICE9_PMDS;i++)
    {
      char tmp[1024];
      sprintf(tmp,"/sys/kernel/perfmon/pmu_desc/pmd%d",i);
      if (access(tmp,F_OK) == 0)
	sicortex_support.pmd_count++;
    }
  for (i=0;i<MAX_ICE9_PMCS;i++)
    {
      char tmp[1024];
      sprintf(tmp,"/sys/kernel/perfmon/pmu_desc/pmc%d",i);
      if (access(tmp,F_OK) == 0)
	sicortex_support.pmc_count++;
    }
  
  /* Compute the max */

  if (type == PFMLIB_MIPS_ICE9A_PMU) {
    gen_mips64_pe = gen_mips64_ice9a_pe;
//    core_counters = 2;
    bound = (sizeof(gen_mips64_ice9a_pe)/sizeof(pme_gen_mips64_entry_t));
  } else if (type == PFMLIB_MIPS_ICE9B_PMU) {
    gen_mips64_pe = gen_mips64_ice9b_pe;
//    core_counters = 2;
    bound = (sizeof(gen_mips64_ice9b_pe)/sizeof(pme_gen_mips64_entry_t));
  }

  /* Allocate the table */

  sicortex_pe = malloc(bound*sizeof(*sicortex_pe));
  if (sicortex_pe == NULL)
    return 0;

  /* If we find we have SCB support */

  if (sicortex_support.pmd_count > 2)
    {
      /* Account for 4 sampling PMD registers */
      sicortex_support.num_cnt = sicortex_support.pmd_count - 4;
      sicortex_support.pme_count = bound;
    }
  else
    {
      sicortex_support.pme_count = 0;
      /* Count up CPU only events */
      for (i=0;i<bound;i++)
	{
	  unsigned int tmp = gen_mips64_pe[i].pme_counters;
	  if (!(tmp & (1<<core_counters)))
	    sicortex_support.pme_count++;
	}
    }

  for (i=0;i<bound;i++)
    {
      sicortex_pe[i].pme_name = gen_mips64_pe[i].pme_name;
      sicortex_pe[i].pme_desc = gen_mips64_pe[i].pme_desc;
      sicortex_pe[i].pme_code = gen_mips64_pe[i].pme_code;
      sicortex_pe[i].pme_counters = gen_mips64_pe[i].pme_counters;
      if (sicortex_pe[i].pme_counters & (1<<core_counters)) {
	int j;
	sicortex_pe[i].pme_numasks = PFMLIB_SICORTEX_MAX_UMASK;
	for (j=0;j<sicortex_pe[i].pme_numasks;j++)
	  {
	    sicortex_pe[i].pme_umasks[j].pme_uname = sicortex_scb_umasks[j].pme_uname;
	    sicortex_pe[i].pme_umasks[j].pme_udesc = sicortex_scb_umasks[j].pme_udesc;
	    sicortex_pe[i].pme_umasks[j].pme_ucode = sicortex_scb_umasks[j].pme_ucode;
	  }
      } else {
	sicortex_pe[i].pme_numasks = 0;
	memset(sicortex_pe[i].pme_umasks,0x0,sizeof(sicortex_pe[i].pme_umasks));
      }
    }
  return 1;
}

static int
pfm_sicortex_detect(void)
{
	static char mips_name[64] = "";
	int ret;
	char buffer[128];
	extern pfm_pmu_support_t sicortex_support;

	ret = __pfm_getcpuinfo_attr("cpu model", buffer, sizeof(buffer));
	if (ret == -1)
		return PFMLIB_ERR_NOTSUPP;

	sicortex_support.num_cnt = 0;
	if (strstr(buffer,"SiCortex ICE9A"))
	  {
	    if (compute_ice9_counters(PFMLIB_MIPS_ICE9A_PMU) == 0)
	      return PFMLIB_ERR_NOTSUPP;
	    sicortex_support.pmu_name = mips_name;
	    strcpy(sicortex_support.pmu_name,"MIPSICE9A"),
	    sicortex_support.pmu_type = PFMLIB_MIPS_ICE9A_PMU;
	  }
	else if (strstr(buffer,"SiCortex ICE9B"))
	  {
	    if (compute_ice9_counters(PFMLIB_MIPS_ICE9B_PMU) == 0)
	      return PFMLIB_ERR_NOTSUPP;
	    sicortex_support.pmu_name = mips_name;
	    strcpy(sicortex_support.pmu_name,"MIPSICE9B"),
	    sicortex_support.pmu_type = PFMLIB_MIPS_ICE9B_PMU;
	  }
	else
	  return PFMLIB_ERR_NOTSUPP;

	if (sicortex_support.num_cnt == 0)
	  sicortex_support.num_cnt = sicortex_support.pmd_count;

	return PFMLIB_SUCCESS;
}

static void stuff_sicortex_regs(pfmlib_event_t *e, int plm, pfmlib_reg_t *pc, pfmlib_reg_t *pd, int cntr, int j, pfmlib_sicortex_input_param_t *mod_in)
{
  pfm_sicortex_sel_reg_t reg;
  reg.val    = 0; /* assume reserved bits are zerooed */
  /* if plm is 0, then assume not specified per-event and use default */
  plm = e[j].plm ? e[j].plm : plm;
  reg.sel_usr = plm & PFM_PLM3 ? 1 : 0;
  reg.sel_os  = plm & PFM_PLM0 ? 1 : 0;
  reg.sel_sup = plm & PFM_PLM1 ? 1 : 0;
  reg.sel_exl = plm & PFM_PLM2 ? 1 : 0;
  reg.sel_int = 1; /* force int to 1 */

  /* CPU event */
  if (sicortex_pe[e[j].event].pme_counters & ((1<<core_counters)-1))
    {
      reg.sel_event_mask = (sicortex_pe[e[j].event].pme_code >> (cntr*8)) & 0xff;
      pc[j].reg_addr    = cntr*2;
      pc[j].reg_value   = reg.val;
      pc[j].reg_num     = cntr;
      
      __pfm_vbprintf("[CP0_25_%u(pmc%u)=0x%"PRIx64" event_mask=0x%x usr=%d os=%d sup=%d exl=%d int=1] %s\n",
		     pc[j].reg_addr,
		     pc[j].reg_num,
		     pc[j].reg_value,
		     reg.sel_event_mask,
		     reg.sel_usr,
		     reg.sel_os,
		     reg.sel_sup,
		     reg.sel_exl,
		     sicortex_pe[e[j].event].pme_name);
      
      pd[j].reg_num  = cntr;
      pd[j].reg_addr = cntr*2 + 1;
      
      __pfm_vbprintf("[CP0_25_%u(pmd%u)]\n",
		     pc[j].reg_addr,
		     pc[j].reg_num);
      
    }
  /* SCB event */
  else
    {
      pmc_sicortex_scb_reg_t scbreg;
      int k;
      scbreg.val = 0;
      scbreg.sicortex_ScbPerfBucket_reg.event = sicortex_pe[e[j].event].pme_code >> 16;
      for (k=0;k<e[j].num_masks;k++)
	{
	  if (e[j].unit_masks[k] == 4)
	    scbreg.sicortex_ScbPerfBucket_reg.hist = 0x1;
	  else if (e[j].unit_masks[k] == 1)
	    scbreg.sicortex_ScbPerfBucket_reg.ifOther = 0x1;
	  else if (e[j].unit_masks[k] == 2)
	    scbreg.sicortex_ScbPerfBucket_reg.ifOther = 0x2;
	}
      __pfm_vbprintf("[ScbPerfBucket[%u](pmc%u)=0x%"PRIx64" event=0x%x hist=%d ifOther=0x%x]\n",
		     cntr,cntr+6,scbreg.val,
		     scbreg.sicortex_ScbPerfBucket_reg.event,
		     scbreg.sicortex_ScbPerfBucket_reg.hist,
		     scbreg.sicortex_ScbPerfBucket_reg.ifOther);
      
      pc[j].reg_addr    = cntr;
      pc[j].reg_value   = scbreg.val;
      pc[j].reg_num     = cntr + 6;
      
      pd[j].reg_addr = cntr;
      pd[j].reg_num  = cntr + 6;
      
      __pfm_vbprintf("[ScbPerfCount[%u](pmd%u)]\n",
		     pc[j].reg_addr,
		     pc[j].reg_num);
      
    }
}

static int stuff_sicortex_scb_control_regs(pfmlib_reg_t *pc, pfmlib_reg_t *pd, int num, pfmlib_sicortex_input_param_t *mod_in)
{
  pmc_sicortex_scb_reg_t two;
  pmc_sicortex_scb_reg_t three;
  pmc_sicortex_scb_reg_t four;
  pmc_sicortex_scb_reg_t five;

  // __pfm_vbprintf("num = %d\n",num);
  
  /* The kernel will enforce most of these, see perfmon_ice9.c in the kernel */

  /* ScbPerfCtl */

  pc[num].reg_num = 2; 
  pc[num].reg_addr = 2; 
  two.val = 0;
  if (mod_in && (mod_in->flags & PFMLIB_SICORTEX_INPUT_SCB_INTERVAL))
    {
      two.sicortex_ScbPerfCtl_reg.Interval = mod_in->pfp_sicortex_scb_global.Interval;
    }
  else
    {
      two.sicortex_ScbPerfCtl_reg.Interval = 6;  /* 2048 cycles */
    }
  if (mod_in && (mod_in->flags & PFMLIB_SICORTEX_INPUT_SCB_NOINC))
    {
      two.sicortex_ScbPerfCtl_reg.NoInc = mod_in->pfp_sicortex_scb_global.NoInc;  
    }
  else
    {
      two.sicortex_ScbPerfCtl_reg.NoInc = 0;
    }

  two.sicortex_ScbPerfCtl_reg.IntBit = 31;   /* Interrupt on last bit */
  two.sicortex_ScbPerfCtl_reg.MagicEvent = 0;
  two.sicortex_ScbPerfCtl_reg.AddrAssert = 1;

  __pfm_vbprintf("[Scb%s(pmc%u)=0x%"PRIx64" Interval=0x%x IntBit=0x%x NoInc=%d AddrAssert=%d MagicEvent=0x%x]\n","PerfCtl",
		 pc[num].reg_num,
		 two.val,
		 two.sicortex_ScbPerfCtl_reg.Interval,
		 two.sicortex_ScbPerfCtl_reg.IntBit,
		 two.sicortex_ScbPerfCtl_reg.NoInc,
		 two.sicortex_ScbPerfCtl_reg.AddrAssert,
		 two.sicortex_ScbPerfCtl_reg.MagicEvent);
  pc[num].reg_value = two.val;

  /*ScbPerfHist */

  pc[++num].reg_num = 3; 
  pc[num].reg_addr = 3;
  three.val = 0;
  if (mod_in && (mod_in->flags & PFMLIB_SICORTEX_INPUT_SCB_HISTGTE))
    three.sicortex_ScbPerfHist_reg.HistGte = mod_in->pfp_sicortex_scb_global.HistGte;
  else
    three.sicortex_ScbPerfHist_reg.HistGte = 1;

  __pfm_vbprintf("[Scb%s(pmc%u)=0x%"PRIx64" HistGte=0x%x]\n","PerfHist",
		 pc[num].reg_num,
		 three.val,
		 three.sicortex_ScbPerfHist_reg.HistGte);
  pc[num].reg_value = three.val;

  /*ScbPerfBuckNum */

  pc[++num].reg_num = 4; 
  pc[num].reg_addr = 4;
  four.val = 0;
  if (mod_in && (mod_in->flags & PFMLIB_SICORTEX_INPUT_SCB_BUCKET))
    four.sicortex_ScbPerfBuckNum_reg.Bucket = mod_in->pfp_sicortex_scb_global.Bucket;
  else
    four.sicortex_ScbPerfBuckNum_reg.Bucket = 0;
  __pfm_vbprintf("[Scb%s(pmc%u)=0x%"PRIx64" Bucket=0x%x]\n","PerfBuckNum",
		 pc[num].reg_num,
		 four.val,
		 four.sicortex_ScbPerfBuckNum_reg.Bucket);
  pc[num].reg_value = four.val;

  /*ScbPerfEna */

  pc[++num].reg_num = 5; 
  pc[num].reg_addr = 5;
  five.val = 0;
  five.sicortex_ScbPerfEna_reg.ena = 1;
  __pfm_vbprintf("[Scb%s(pmc%u)=0x%"PRIx64" ena=%d]\n","PerfEna",
		 pc[num].reg_num,
		 five.val,
		 five.sicortex_ScbPerfEna_reg.ena);
  pc[num].reg_value = five.val;
  ++num;
  return(num);
}

/*
 * Automatically dispatch events to corresponding counters following constraints.
 * Upon return the pfarg_regt structure is ready to be submitted to kernel
 */
static int
pfm_sicortex_dispatch_counters(pfmlib_input_param_t *inp, pfmlib_sicortex_input_param_t *mod_in, pfmlib_output_param_t *outp)
{
        /* pfmlib_sicortex_input_param_t *param = mod_in; */
	pfmlib_event_t *e = inp->pfp_events;
	pfmlib_reg_t *pc, *pd;
	unsigned int i, j, cnt = inp->pfp_event_count;
	unsigned int used = 0;
	extern pfm_pmu_support_t sicortex_support;
	unsigned int cntr, avail;

	pc = outp->pfp_pmcs;
	pd = outp->pfp_pmds;

	/* Degree N rank based allocation */
	if (cnt > sicortex_support.pmc_count) return PFMLIB_ERR_TOOMANY;

	if (PFMLIB_DEBUG()) {
	  for (j=0; j < cnt; j++) {
	    DPRINT("ev[%d]=%s, counters=0x%x\n", j, sicortex_pe[e[j].event].pme_name,sicortex_pe[e[j].event].pme_counters);
	  }
	}

      /* Do rank based allocation, counters that live on 1 reg 
	   before counters that live on 2 regs etc. */

      /* CPU counters first */
	for (i=1;i<=core_counters;i++)
	  {
	    for (j=0; j < cnt;j++) 
	      {
		/* CPU counters first */
		if ((sicortex_pe[e[j].event].pme_counters & ((1<<core_counters)-1)) && (pfmlib_popcnt(sicortex_pe[e[j].event].pme_counters) == i))
		  {
		    /* These counters can be used for this event */
		    avail = ~used & sicortex_pe[e[j].event].pme_counters;
		    DPRINT("Rank %d: Counters available 0x%x\n",i,avail);
		    if (avail == 0x0)
		      return PFMLIB_ERR_NOASSIGN;

		    /* Pick one, mark as used*/
		    cntr = ffs(avail) - 1;
		    DPRINT("Rank %d: Chose counter %d\n",i,cntr);
	    
		    /* Update registers */
		    stuff_sicortex_regs(e,inp->pfp_dfl_plm,pc,pd,cntr,j,mod_in);
		    
		    used |= (1 << cntr);
		    DPRINT("Rank %d: Used counters 0x%x\n",i, used);
		  }
	      }
	  }

      /* SCB counters can live anywhere */
	
	used = 0;
	for (j=0; j < cnt;j++) 
	  {
	    unsigned int cntr;

	    /* CPU counters first */
	    if (sicortex_pe[e[j].event].pme_counters & (1<<core_counters))
	      {
		int k, has_ifother = 0, has_hist = 0;
		for (k=0;k<e[j].num_masks;k++)
		  {
		    if ((e[j].unit_masks[k] == 0) || (e[j].unit_masks[k] == 1) || (e[j].unit_masks[k] == 2)) {
		      if (has_ifother)
			return PFMLIB_ERR_UMASK;
		      has_ifother = 1;
		    }
		    else if ((e[j].unit_masks[k] == 3) || (e[j].unit_masks[k] == 4)) {
		      if (has_hist)
			return PFMLIB_ERR_UMASK;
		      has_hist = 1;
		    }
		  }
		/* These counters can be used for this event */
		avail = sicortex_support.num_cnt - core_counters - used;
		DPRINT("SCB(%d): Counters available %d\n",j,avail);
	    
		cntr = (sicortex_support.num_cnt - core_counters) - avail;
		DPRINT("SCB(%d): Chose SCB counter %d\n",j,cntr);

		/* Update registers */
		stuff_sicortex_regs(e,inp->pfp_dfl_plm,pc,pd,cntr,j,mod_in);
		used++;
		DPRINT("SCB(%d): Used counters %d\n",j,used);
	      }
	  }
	if (used)
	  {
	    outp->pfp_pmc_count = stuff_sicortex_scb_control_regs(pc,pd,cnt,mod_in);
	    outp->pfp_pmd_count = cnt;
	    return PFMLIB_SUCCESS;
	  }

	/* number of evtsel registers programmed */
	outp->pfp_pmc_count = cnt;
	outp->pfp_pmd_count = cnt;

	return PFMLIB_SUCCESS;
}

static int
pfm_sicortex_dispatch_events(pfmlib_input_param_t *inp, void *model_in, pfmlib_output_param_t *outp, void *model_out)
{
	pfmlib_sicortex_input_param_t *mod_sicortex_in  = (pfmlib_sicortex_input_param_t *)model_in;

	return pfm_sicortex_dispatch_counters(inp, mod_sicortex_in, outp);
}

static int
pfm_sicortex_get_event_code(unsigned int i, unsigned int cnt, int *code)
{
	extern pfm_pmu_support_t sicortex_support;

	/* check validity of counter index */
	if (cnt != PFMLIB_CNT_FIRST) {
	  if (cnt < 0 || cnt >= sicortex_support.pmc_count)
	    return PFMLIB_ERR_INVAL; }
	else 	  {
	    cnt = ffs(sicortex_pe[i].pme_counters)-1;
	    if (cnt == -1)
	      return(PFMLIB_ERR_INVAL);
	  }
 
	/* if cnt == 1, shift right by 0, if cnt == 2, shift right by 8 */
	/* Works on both 5k anf 20K */

	    unsigned int tmp = sicortex_pe[i].pme_counters;
	    /* CPU event */
	    if (tmp & ((1<<core_counters)-1))
	      {
		if (tmp & (1<< cnt))
		  *code = 0xff & (sicortex_pe[i].pme_code >> (cnt*8));
		else
		  return PFMLIB_ERR_INVAL;
	      }
	    /* SCB event */
	    else 
	      {
		if ((cnt < 6) || (cnt >= sicortex_support.pmc_count))
		  return PFMLIB_ERR_INVAL;
		*code = 0xffff & (sicortex_pe[i].pme_code >> 16);
	      }

	return PFMLIB_SUCCESS;
}

/*
 * This function is accessible directly to the user
 */
int
pfm_sicortex_get_event_umask(unsigned int i, unsigned long *umask)
{
	extern pfm_pmu_support_t sicortex_support;
	if (i >= sicortex_support.pme_count || umask == NULL) return PFMLIB_ERR_INVAL;
	*umask = 0; //evt_umask(i);
	return PFMLIB_SUCCESS;
}
	
static void
pfm_sicortex_get_event_counters(unsigned int j, pfmlib_regmask_t *counters)
{
	extern pfm_pmu_support_t sicortex_support;
	unsigned int tmp;

	memset(counters, 0, sizeof(*counters));
	tmp = sicortex_pe[j].pme_counters;

	/* CPU counter */
	if (tmp & ((1<<core_counters)-1))
	  {
	    while (tmp)
	      {
		int t = ffs(tmp) - 1;
		pfm_regmask_set(counters, t);
		tmp = tmp ^ (1 << t);
	      }
	  }
	/* SCB counter, requires first 4, then 1 of the remaining */
	else 
	  {
	    int i;
	    for (i=6;i<sicortex_support.pmc_count;i++)
	      pfm_regmask_set(counters, i);
	  }
}

static void
pfm_sicortex_get_impl_perfsel(pfmlib_regmask_t *impl_pmcs)
{
	unsigned int i = 0;
	extern pfm_pmu_support_t sicortex_support;

	/* all pmcs are contiguous */
	for(i=0; i < sicortex_support.pmc_count; i++) pfm_regmask_set(impl_pmcs, i);
}

static void
pfm_sicortex_get_impl_perfctr(pfmlib_regmask_t *impl_pmds)
{
	unsigned int i = 0;
	extern pfm_pmu_support_t sicortex_support;

	/* all pmds are contiguous */
	for(i=0; i < sicortex_support.pmd_count; i++) pfm_regmask_set(impl_pmds, i);
}

static void
pfm_sicortex_get_impl_counters(pfmlib_regmask_t *impl_counters)
{
	unsigned int i = 0;
	extern pfm_pmu_support_t sicortex_support;

	pfm_regmask_set(impl_counters, 0);
	pfm_regmask_set(impl_counters, 1);
	/* If we have the SCB turned on */
	if (sicortex_support.pmd_count > core_counters)
	  {
	    /* counting pmds are not contiguous on ICE9*/
	    for(i=6; i < sicortex_support.pmd_count; i++) 
	      pfm_regmask_set(impl_counters, i);
	  }
}

static void
pfm_sicortex_get_hw_counter_width(unsigned int *width)
{
	*width = PMU_GEN_MIPS64_COUNTER_WIDTH;
}

static char *
pfm_sicortex_get_event_name(unsigned int i)
{
	return sicortex_pe[i].pme_name;
}

static int
pfm_sicortex_get_event_description(unsigned int ev, char **str)
{
	char *s;
	s = sicortex_pe[ev].pme_desc;
	if (s) {
		*str = strdup(s);
	} else {
		*str = NULL;
	}
	return PFMLIB_SUCCESS;
}

static int
pfm_sicortex_get_cycle_event(pfmlib_event_t *e)
{
  return pfm_find_full_event("CPU_CYCLES",e);
}

static int
pfm_sicortex_get_inst_retired(pfmlib_event_t *e)
{
  return pfm_find_full_event("CPU_INSEXEC",e); 
}

/* SiCortex specific functions */

/* CPU counter */
int pfm_sicortex_is_cpu(unsigned int i)
{
  if (i < sicortex_support.pme_count)
    {
      unsigned int tmp = sicortex_pe[i].pme_counters;
      return !(tmp & (1<<core_counters));
    }
  return 0;
}

/* SCB counter */
int pfm_sicortex_is_scb(unsigned int i)
{
  if (i < sicortex_support.pme_count)
    {
      unsigned int tmp = sicortex_pe[i].pme_counters;
      return (tmp & (1<<core_counters));
    }
  return 0;
}

/* Reg 25 domain support */
int pfm_sicortex_support_domain(unsigned int i)
{
  if (i < sicortex_support.pme_count)
    {
      unsigned int tmp = sicortex_pe[i].pme_counters;
      return (tmp & (1<<3));
    }
  return 0;
}

/* VPC/PEA sampling support */
int pfm_sicortex_support_vpc_pea(unsigned int i)
{
  if (i < sicortex_support.pme_count)
    {
      unsigned int tmp = sicortex_pe[i].pme_counters;
      return (tmp & (1<<4));  
    }
  return 0;
}

static char *
pfm_sicortex_get_event_mask_name(unsigned int ev, unsigned int midx)
{
  return sicortex_pe[ev].pme_umasks[midx].pme_uname;
}

static int
pfm_sicortex_get_event_mask_desc(unsigned int ev, unsigned int midx, char **str)
{
  char *s;
  
  s = sicortex_pe[ev].pme_umasks[midx].pme_udesc;
  if (s) {
    *str = strdup(s);
  } else {
    *str = NULL;
  }
  return PFMLIB_SUCCESS;
}

static unsigned int
pfm_sicortex_get_num_event_masks(unsigned int ev)
{
  return sicortex_pe[ev].pme_numasks;
}

static int
pfm_sicortex_get_event_mask_code(unsigned int ev, unsigned int midx, unsigned int *code)
{
  *code = sicortex_pe[ev].pme_umasks[midx].pme_ucode;
  return PFMLIB_SUCCESS;
}

static int
pfm_sicortex_has_umask_default(unsigned int ev)
{
	/* all events have default unit mask */
	return 1;
}

pfm_pmu_support_t sicortex_support = {
	.pmu_name		= NULL,
	.pmu_type		= PFMLIB_UNKNOWN_PMU,
	.pme_count		= 0,
	.pmc_count		= 0,
	.pmd_count		= 0,
	.num_cnt		= 0,
	.flags			= PFMLIB_MULT_CODE_EVENT,
	.get_event_code		= pfm_sicortex_get_event_code,
	.get_event_name		= pfm_sicortex_get_event_name,
	.get_event_counters	= pfm_sicortex_get_event_counters,
	.dispatch_events	= pfm_sicortex_dispatch_events,
	.pmu_detect		= pfm_sicortex_detect,
	.get_impl_pmcs		= pfm_sicortex_get_impl_perfsel,
	.get_impl_pmds		= pfm_sicortex_get_impl_perfctr,
	.get_impl_counters	= pfm_sicortex_get_impl_counters,
	.get_hw_counter_width	= pfm_sicortex_get_hw_counter_width,
	.get_event_desc         = pfm_sicortex_get_event_description,
	.get_num_event_masks	= pfm_sicortex_get_num_event_masks,
	.get_event_mask_name	= pfm_sicortex_get_event_mask_name,
	.get_event_mask_code	= pfm_sicortex_get_event_mask_code,
	.get_event_mask_desc	= pfm_sicortex_get_event_mask_desc,
	.get_cycle_event	= pfm_sicortex_get_cycle_event,
	.get_inst_retired_event = pfm_sicortex_get_inst_retired,
	.has_umask_default	= pfm_sicortex_has_umask_default
};
