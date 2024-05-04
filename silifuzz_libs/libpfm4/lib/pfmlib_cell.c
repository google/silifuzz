/*
 * pfmlib_cell.c : support for the Cell PMU family
 *
 * Copyright (c) 2007 TOSHIBA CORPORATION based on code from
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
#include <stdlib.h>

/* public headers */
#include <perfmon/pfmlib_cell.h>

/* private headers */
#include "pfmlib_priv.h"	/* library private */
#include "pfmlib_cell_priv.h"	/* architecture private */
#include "cell_events.h"	/* PMU private */

#define SIGNAL_TYPE_CYCLES      0
#define PM_COUNTER_CTRL_CYLES   0x42C00000U

#define PFM_CELL_NUM_PMCS	24
#define PFM_CELL_EVENT_MIN	1
#define PFM_CELL_EVENT_MAX	8
#define PMX_MIN_NUM		1
#define PMX_MAX_NUM		8
#define PFM_CELL_16BIT_CNTR_EVENT_MAX 8
#define PFM_CELL_32BIT_CNTR_EVENT_MAX 4

#define COMMON_REG_NUMS		8

#define ENABLE_WORD0		0
#define ENABLE_WORD1		1
#define ENABLE_WORD2		2

#define PFM_CELL_GRP_CONTROL_REG_GRP0_BIT	30
#define PFM_CELL_GRP_CONTROL_REG_GRP1_BIT	28
#define PFM_CELL_BASE_WORD_UNIT_FIELD_BIT	24
#define PFM_CELL_WORD_UNIT_FIELD_WIDTH		2
#define PFM_CELL_MAX_WORD_NUMBER		3
#define PFM_CELL_COUNTER_CONTROL_GRP1		0x80000000U
#define PFM_CELL_DEFAULT_TRIGGER_EVENT_UNIT     0x00555500U
#define PFM_CELL_PM_CONTROL_16BIT_CNTR_MASK     0x01E00000U
#define PFM_CELL_PM_CONTROL_PPU_CNTR_MODE_PROBLEM    0x00080000U
#define PFM_CELL_PM_CONTROL_PPU_CNTR_MODE_SUPERVISOR 0x00000000U
#define PFM_CELL_PM_CONTROL_PPU_CNTR_MODE_HYPERVISOR 0x00040000U
#define PFM_CELL_PM_CONTROL_PPU_CNTR_MODE_ALL        0x000C0000U
#define PFM_CELL_PM_CONTROL_PPU_CNTR_MODE_MASK       0x000C0000U

#define ONLY_WORD(x) \
	((x == WORD_0_ONLY)||(x == WORD_2_ONLY)) ? x : 0

struct pfm_cell_signal_group_desc {
	unsigned int		signal_type;
	unsigned int		word_type;
	unsigned long long	word;
	unsigned long long	freq;
	unsigned int            subunit;
};

#define swap_int(num1, num2) do {	\
	int tmp = num1;			\
	num1 = num2;			\
	num2 = tmp;			\
} while(0)

static int
pfm_cell_detect(void)
{
	int ret;
	char buffer[128];
	
	ret = __pfm_getcpuinfo_attr("cpu", buffer, sizeof(buffer));
	if (ret == -1) {
		return PFMLIB_ERR_NOTSUPP;
	}
	if (strcmp(buffer, "Cell Broadband Engine, altivec supported")) {
		return PFMLIB_ERR_NOTSUPP;
	}

	return PFMLIB_SUCCESS;
}

static int
get_pmx_offset(int pmx_num, unsigned int *pmx_ctrl_bits)
{
	/* pmx_num==0 -> not specified
	 * pmx_num==1 -> pm0
	 *            :
	 * pmx_num==8 -> pm7
	 */
	int i = 0;
	int offset;
	
	if ((pmx_num >= PMX_MIN_NUM) && (pmx_num <= PMX_MAX_NUM)) {
		/* offset is specified */
		offset = (pmx_num - 1);
		
		if ((~*pmx_ctrl_bits >> offset) & 0x1) {
			*pmx_ctrl_bits |= (0x1 << offset);
			return offset;
		} else {
			/* offset is used */
			return PFMLIB_ERR_INVAL;
		}
	} else if (pmx_num == 0){
		/* offset is not specified */
		while (((*pmx_ctrl_bits >> i) & 0x1) && (i < PMX_MAX_NUM)) {
			i++;
		}
		*pmx_ctrl_bits |= (0x1 << i);
		return i;
	}
	/* pmx_num is invalid */
	return PFMLIB_ERR_INVAL;
}

static unsigned long long
search_enable_word(int word)
{
	unsigned long long count = 0;
	
	while ((~word) & 0x1) {
		count++;
		word >>= 1;
	}
	return count;
}

static int get_count_bit(unsigned int type)
{
	int count = 0;

	while(type) {
		if (type & 1) {
			count++;
		}
		type >>= 1;
	}
	return count;
}


static int
get_debug_bus_word(struct pfm_cell_signal_group_desc *group0, struct pfm_cell_signal_group_desc *group1)
{
	unsigned int word_type0, word_type1;

	/* search enable word  */
	word_type0 = group0->word_type;
	word_type1 = group1->word_type;

	if (group1->signal_type == NONE_SIGNAL) {
		group0->word = search_enable_word(word_type0);
		goto found;
	}

	/* swap */
	if ((get_count_bit(word_type0) > get_count_bit(word_type1)) ||
	    (group0->freq == PFM_CELL_PME_FREQ_SPU)) {
		swap_int(group0->signal_type, group1->signal_type);
		swap_int(group0->freq, group1->freq);
		swap_int(group0->word_type, group1->word_type);
		swap_int(group0->subunit, group1->subunit);
		swap_int(word_type0, word_type1);
	}

	if ((ONLY_WORD(word_type0) != 0) && (word_type0 == word_type1)) {
		return PFMLIB_ERR_INVAL;
	}

	if (ONLY_WORD(word_type0)) {
		group0->word = search_enable_word(ONLY_WORD(word_type0));

		word_type1 &= ~(1UL << (group0->word));
		group1->word = search_enable_word(word_type1);
	} else if (ONLY_WORD(word_type1)) {
		group1->word = search_enable_word(ONLY_WORD(word_type1));

		word_type0 &= ~(1UL << (group1->word));
		group0->word = search_enable_word(word_type0);
	} else {
		group0->word = ENABLE_WORD0;
		if (word_type1 == WORD_0_AND_1) {
			group1->word = ENABLE_WORD1;
		} else if(word_type1 == WORD_0_AND_2) {
			group1->word = ENABLE_WORD2;
		} else {
			return PFMLIB_ERR_INVAL;
		}
	}

found:
	return PFMLIB_SUCCESS;
}

static unsigned int get_signal_type(unsigned long long event_code) 
{
	return (event_code & 0x00000000FFFFFFFFULL) / 100;
}	

static unsigned int get_signal_bit(unsigned long long event_code) 
{
	return (event_code & 0x00000000FFFFFFFFULL) % 100;
}	

static int is_spe_signal_group(unsigned int signal_type)
{
	if (41 <= signal_type && signal_type <= 56) {
		return 1;
	} else {
		return 0;
	}
}

static int
check_signal_type(pfmlib_input_param_t *inp,
		  pfmlib_cell_input_param_t *mod_in,
		  struct pfm_cell_signal_group_desc *group0,
		  struct pfm_cell_signal_group_desc *group1)
{
	pfmlib_event_t *e;
	unsigned int event_cnt;
	int signal_cnt = 0;
	int i;
	int cycles_signal_cnt = 0;
	unsigned int signal_type, subunit;

	e		= inp->pfp_events;
	event_cnt	= inp->pfp_event_count;

	for(i = 0; i < event_cnt; i++) {
		signal_type = get_signal_type(cell_pe[e[i].event].pme_code);

		if ((signal_type == SIGNAL_SPU_TRIGGER)
		    || (signal_type == SIGNAL_SPU_EVENT)) {
			continue;
		}

		if (signal_type == SIGNAL_TYPE_CYCLES) {
			cycles_signal_cnt = 1;
			continue;
		}

		subunit = 0;
		if (is_spe_signal_group(signal_type)) {
			subunit = mod_in->pfp_cell_counters[i].spe_subunit;
		}
		switch(signal_cnt) {
			case 0:
				group0->signal_type = signal_type;
				group0->word_type = cell_pe[e[i].event].pme_enable_word;
				group0->freq = cell_pe[e[i].event].pme_freq;
				group0->subunit = subunit;
				signal_cnt++;
				break;
				
			case 1:
				if ((group0->signal_type != signal_type) ||
				    (is_spe_signal_group(signal_type) && group0->subunit != subunit)) {
					group1->signal_type = signal_type;
					group1->word_type = cell_pe[e[i].event].pme_enable_word;
					group1->freq = cell_pe[e[i].event].pme_freq;
					group1->subunit = subunit;
					signal_cnt++;
					
				}
				break;
				
			case 2:
				if ((group0->signal_type != signal_type)
				  && (group1->signal_type != signal_type)) {
					DPRINT("signal count is invalid\n");
					return PFMLIB_ERR_INVAL;
				}
				break;
				
			default:
				DPRINT("signal count is invalid\n");
				return PFMLIB_ERR_INVAL;
		}
	}
	return (signal_cnt + cycles_signal_cnt);
}

/*
 * The assignment between the privilege leve options
 * and ppu-count-mode field in pm_control register.
 *
 * option         ppu count mode(pm_control)
 * ---------------------------------
 * -u(-3)        0b10 : Problem mode
 * -k(-0)        0b00 : Supervisor mode
 * -1            0b00 : Supervisor mode
 * -2            0b01 : Hypervisor mode
 * two options   0b11 : Any mode
 *
 * Note : Hypervisor-mode and Any-mode don't work on PS3.
 *
 */
static unsigned int get_ppu_count_mode(unsigned int plm)
{
	unsigned int ppu_count_mode = 0;

	switch (plm) {
	case PFM_PLM0:
	case PFM_PLM1:
		ppu_count_mode = PFM_CELL_PM_CONTROL_PPU_CNTR_MODE_SUPERVISOR;
		break;

	case PFM_PLM2:
		ppu_count_mode = PFM_CELL_PM_CONTROL_PPU_CNTR_MODE_HYPERVISOR;
		break;

	case PFM_PLM3:
		ppu_count_mode = PFM_CELL_PM_CONTROL_PPU_CNTR_MODE_PROBLEM;
		break;

	default :
		ppu_count_mode = PFM_CELL_PM_CONTROL_PPU_CNTR_MODE_ALL;
		break;
	}
	return ppu_count_mode;
}

static int
pfm_cell_dispatch_counters(pfmlib_input_param_t *inp,
			   pfmlib_cell_input_param_t *mod_in,
			   pfmlib_output_param_t *outp)
{
	pfmlib_event_t *e;
	pfmlib_reg_t *pc, *pd;
	unsigned int event_cnt;
	unsigned int signal_cnt = 0, pmcs_cnt = 0;
	unsigned int signal_type;
	unsigned long long signal_bit;
	struct pfm_cell_signal_group_desc group[2];
	int pmx_offset = 0;
	int i, ret;
	int input_control, polarity, count_cycle, count_enable;
	unsigned long long subunit;
	int shift0, shift1;
	unsigned int pmx_ctrl_bits;
	int max_event_cnt = PFM_CELL_32BIT_CNTR_EVENT_MAX;
	
	count_enable = 1;

	group[0].signal_type = group[1].signal_type = NONE_SIGNAL;
	group[0].word = group[1].word = 0L;
	group[0].freq = group[1].freq = 0L;
	group[0].subunit = group[1].subunit = 0;
	group[0].word_type = group[1].word_type = WORD_NONE;

	event_cnt = inp->pfp_event_count;
	e = inp->pfp_events;
	pc = outp->pfp_pmcs;
	pd = outp->pfp_pmds;

	/* check event_cnt */
	if (mod_in->control & PFM_CELL_PM_CONTROL_16BIT_CNTR_MASK)
		max_event_cnt = PFM_CELL_16BIT_CNTR_EVENT_MAX;
	if (event_cnt < PFM_CELL_EVENT_MIN)
		return PFMLIB_ERR_NOTFOUND;
	if (event_cnt > max_event_cnt)
		return PFMLIB_ERR_TOOMANY;

	/* check signal type */
	signal_cnt = check_signal_type(inp, mod_in, &group[0], &group[1]);
	if (signal_cnt == PFMLIB_ERR_INVAL)
		return PFMLIB_ERR_NOASSIGN;

	/* decide debug_bus word */
	if (signal_cnt != 0 && group[0].signal_type != NONE_SIGNAL) {
		ret = get_debug_bus_word(&group[0], &group[1]);
		if (ret != PFMLIB_SUCCESS)
			return PFMLIB_ERR_NOASSIGN;
	}

	/* common register setting */
	pc[pmcs_cnt].reg_num	= REG_GROUP_CONTROL;
	if (signal_cnt == 1) {
		pc[pmcs_cnt].reg_value =
			group[0].word << PFM_CELL_GRP_CONTROL_REG_GRP0_BIT;
	} else if (signal_cnt == 2) {
		pc[pmcs_cnt].reg_value =
			(group[0].word << PFM_CELL_GRP_CONTROL_REG_GRP0_BIT) |
			(group[1].word << PFM_CELL_GRP_CONTROL_REG_GRP1_BIT);
	}
	pmcs_cnt++;

	pc[pmcs_cnt].reg_num	= REG_DEBUG_BUS_CONTROL;
	if (signal_cnt == 1) {
		shift0 = PFM_CELL_BASE_WORD_UNIT_FIELD_BIT +
			((PFM_CELL_MAX_WORD_NUMBER - group[0].word) *
			 PFM_CELL_WORD_UNIT_FIELD_WIDTH);
		pc[pmcs_cnt].reg_value = group[0].freq << shift0;
	} else if (signal_cnt == 2) {
		shift0 = PFM_CELL_BASE_WORD_UNIT_FIELD_BIT +
			((PFM_CELL_MAX_WORD_NUMBER - group[0].word) *
			 PFM_CELL_WORD_UNIT_FIELD_WIDTH);
		shift1 = PFM_CELL_BASE_WORD_UNIT_FIELD_BIT +
			((PFM_CELL_MAX_WORD_NUMBER - group[1].word) *
			 PFM_CELL_WORD_UNIT_FIELD_WIDTH);
		pc[pmcs_cnt].reg_value = (group[0].freq << shift0) |
			(group[1].freq << shift1);
	}
	pc[pmcs_cnt].reg_value |= PFM_CELL_DEFAULT_TRIGGER_EVENT_UNIT;
	pmcs_cnt++;

	pc[pmcs_cnt].reg_num	= REG_TRACE_ADDRESS;
	pc[pmcs_cnt].reg_value	= 0;
	pmcs_cnt++;

	pc[pmcs_cnt].reg_num	= REG_EXT_TRACE_TIMER;
	pc[pmcs_cnt].reg_value	= 0;
	pmcs_cnt++;

	pc[pmcs_cnt].reg_num	= REG_PM_STATUS;
	pc[pmcs_cnt].reg_value	= 0;
	pmcs_cnt++;

	pc[pmcs_cnt].reg_num	= REG_PM_CONTROL;
	pc[pmcs_cnt].reg_value	=
		(mod_in->control & ~PFM_CELL_PM_CONTROL_PPU_CNTR_MODE_MASK) |
		get_ppu_count_mode(inp->pfp_dfl_plm);
	pmcs_cnt++;

	pc[pmcs_cnt].reg_num	= REG_PM_INTERVAL;
	pc[pmcs_cnt].reg_value	= mod_in->interval;
	pmcs_cnt++;

	pc[pmcs_cnt].reg_num	= REG_PM_START_STOP;
	pc[pmcs_cnt].reg_value	= mod_in->triggers;
	pmcs_cnt++;

	pmx_ctrl_bits = 0;

	/* pmX register setting */
	for(i = 0; i < event_cnt; i++) {
		/* PMX_CONTROL */
		pmx_offset = get_pmx_offset(mod_in->pfp_cell_counters[i].pmX_control_num,
					    &pmx_ctrl_bits);
		if (pmx_offset == PFMLIB_ERR_INVAL) {
			DPRINT("pmX already used\n");
			return PFMLIB_ERR_INVAL;
		}

		signal_type = get_signal_type(cell_pe[e[i].event].pme_code);
		if (signal_type == SIGNAL_TYPE_CYCLES) {
			pc[pmcs_cnt].reg_value	= PM_COUNTER_CTRL_CYLES;
			pc[pmcs_cnt].reg_num	= REG_PM0_CONTROL + pmx_offset;
			pmcs_cnt++;
			pc[pmcs_cnt].reg_value  = cell_pe[e[i].event].pme_code;
			pc[pmcs_cnt].reg_num	= REG_PM0_EVENT + pmx_offset;
			pmcs_cnt++;
			pd[i].reg_num = pmx_offset;
			pd[i].reg_value = 0;
			continue;
		}

		switch(cell_pe[e[i].event].pme_type) {
			case COUNT_TYPE_BOTH_TYPE:
			case COUNT_TYPE_CUMULATIVE_LEN:
			case COUNT_TYPE_MULTI_CYCLE:
			case COUNT_TYPE_SINGLE_CYCLE:
				count_cycle = 1;
				break;
				
			case COUNT_TYPE_OCCURRENCE:
				count_cycle = 0;
				break;
				
			default:
				return PFMLIB_ERR_INVAL;
		}

		signal_bit = get_signal_bit(cell_pe[e[i].event].pme_code);
		polarity = mod_in->pfp_cell_counters[i].polarity;
		input_control = mod_in->pfp_cell_counters[i].input_control;
		subunit = 0;
		if (is_spe_signal_group(signal_type)) {
			subunit = mod_in->pfp_cell_counters[i].spe_subunit;
		}
		
		pc[pmcs_cnt].reg_value	= ( (signal_bit << (31 - 5))
					  | (input_control << (31 - 6))
					  | (polarity << (31 - 7))
					  | (count_cycle << (31 - 8))
					  | (count_enable << (31 - 9)) );
		pc[pmcs_cnt].reg_num	= REG_PM0_CONTROL + pmx_offset;

		if (signal_type == group[1].signal_type && subunit == group[1].subunit) {
			pc[pmcs_cnt].reg_value |= PFM_CELL_COUNTER_CONTROL_GRP1;
		}

		pmcs_cnt++;

		/* PMX_EVENT */
		pc[pmcs_cnt].reg_num	= REG_PM0_EVENT + pmx_offset;

		/* debug bus word setting */
		if (signal_type == group[0].signal_type && subunit == group[0].subunit) {
			pc[pmcs_cnt].reg_value	= (cell_pe[e[i].event].pme_code |
						   (group[0].word << 48) | (subunit << 32));
		} else if (signal_type == group[1].signal_type && subunit == group[1].subunit) {
			pc[pmcs_cnt].reg_value	= (cell_pe[e[i].event].pme_code |
						   (group[1].word << 48) | (subunit << 32));
		} else if ((signal_type == SIGNAL_SPU_TRIGGER)
		           || (signal_type == SIGNAL_SPU_EVENT)) {
			pc[pmcs_cnt].reg_value	= cell_pe[e[i].event].pme_code | (subunit << 32);
		} else {
			return PFMLIB_ERR_INVAL;
		}
		pmcs_cnt++;

		/* pmd setting */
		pd[i].reg_num = pmx_offset;
		pd[i].reg_value = 0;
	}

	outp->pfp_pmc_count = pmcs_cnt;
	outp->pfp_pmd_count = event_cnt;

	return PFMLIB_SUCCESS;
}

static int
pfm_cell_dispatch_events(pfmlib_input_param_t *inp, void *model_in, pfmlib_output_param_t *outp, void *model_out)
{
	pfmlib_cell_input_param_t *mod_in  = (pfmlib_cell_input_param_t *)model_in;
        pfmlib_cell_input_param_t default_model_in;
	int i;

	if (model_in) {
		mod_in = (pfmlib_cell_input_param_t *)model_in;
	} else {
		mod_in = &default_model_in;
		mod_in->control = 0x80000000;
		mod_in->interval = 0;
		mod_in->triggers = 0;
		for (i = 0; i < PMU_CELL_NUM_COUNTERS; i++) {
			mod_in->pfp_cell_counters[i].pmX_control_num = 0;
			mod_in->pfp_cell_counters[i].spe_subunit = 0;
			mod_in->pfp_cell_counters[i].polarity = 1;
			mod_in->pfp_cell_counters[i].input_control = 0;
			mod_in->pfp_cell_counters[i].cnt_mask = 0;
			mod_in->pfp_cell_counters[i].flags = 0;
		}
	}

	return pfm_cell_dispatch_counters(inp, mod_in, outp);
}

static int
pfm_cell_get_event_code(unsigned int i, unsigned int cnt, int *code)
{
//	if (cnt != PFMLIB_CNT_FIRST && cnt > 2) {
	if (cnt != PFMLIB_CNT_FIRST && cnt > cell_support.num_cnt) {
		return PFMLIB_ERR_INVAL;
	}

	*code = cell_pe[i].pme_code;

	return PFMLIB_SUCCESS;
}

static void
pfm_cell_get_event_counters(unsigned int j, pfmlib_regmask_t *counters)
{
	unsigned int i;

	memset(counters, 0, sizeof(*counters));

	for(i=0; i < PMU_CELL_NUM_COUNTERS; i++) {
		pfm_regmask_set(counters, i);
	}
}

static void
pfm_cell_get_impl_pmcs(pfmlib_regmask_t *impl_pmcs)
{
	unsigned int i;

	memset(impl_pmcs, 0, sizeof(*impl_pmcs));

	for(i=0; i < PFM_CELL_NUM_PMCS; i++) {
		pfm_regmask_set(impl_pmcs, i);
	}
}

static void
pfm_cell_get_impl_pmds(pfmlib_regmask_t *impl_pmds)
{
	unsigned int i;

	memset(impl_pmds, 0, sizeof(*impl_pmds));

	for(i=0; i < PMU_CELL_NUM_PERFCTR; i++) {
		pfm_regmask_set(impl_pmds, i);
	}
}

static void
pfm_cell_get_impl_counters(pfmlib_regmask_t *impl_counters)
{
	unsigned int i;

	for(i=0; i < PMU_CELL_NUM_COUNTERS; i++) {
		pfm_regmask_set(impl_counters, i);
	}
}

static char*
pfm_cell_get_event_name(unsigned int i)
{
	return cell_pe[i].pme_name;
}

static int
pfm_cell_get_event_desc(unsigned int ev, char **str)
{
	char *s;

	s = cell_pe[ev].pme_desc;
	if (s) {
		*str = strdup(s);
	} else {
		*str = NULL;
	}
	return PFMLIB_SUCCESS;
}

static int
pfm_cell_get_cycle_event(pfmlib_event_t *e)
{
	int i;

	for (i = 0; i < PME_CELL_EVENT_COUNT; i++) {
		if (!strcmp(cell_pe[i].pme_name, "CYCLES")) {
			e->event = i;
			return PFMLIB_SUCCESS;
		}
	}
	return PFMLIB_ERR_NOTFOUND;
}

int pfm_cell_spe_event(unsigned int event_index)
{
	if (event_index >= PME_CELL_EVENT_COUNT)
		return 0;

	return is_spe_signal_group(get_signal_type(cell_pe[event_index].pme_code));
}

pfm_pmu_support_t cell_support={
	.pmu_name		= "CELL",
	.pmu_type		= PFMLIB_CELL_PMU,
	.pme_count		= PME_CELL_EVENT_COUNT,
	.pmc_count		= PFM_CELL_NUM_PMCS,
	.pmd_count		= PMU_CELL_NUM_PERFCTR,
	.num_cnt		= PMU_CELL_NUM_COUNTERS,
	.get_event_code		= pfm_cell_get_event_code,
	.get_event_name		= pfm_cell_get_event_name,
	.get_event_counters	= pfm_cell_get_event_counters,
	.dispatch_events	= pfm_cell_dispatch_events,
	.pmu_detect		= pfm_cell_detect,
	.get_impl_pmcs		= pfm_cell_get_impl_pmcs,
	.get_impl_pmds		= pfm_cell_get_impl_pmds,
	.get_impl_counters	= pfm_cell_get_impl_counters,
	.get_event_desc		= pfm_cell_get_event_desc,
	.get_cycle_event        = pfm_cell_get_cycle_event
};
