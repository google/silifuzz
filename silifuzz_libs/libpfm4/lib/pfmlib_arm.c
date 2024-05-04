/*
 * pfmlib_arm.c : 	support for ARM chips
 * 
 * Copyright (c) 2010 University of Tennessee
 * Contributed by Vince Weaver <vweaver1@utk.edu>
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
 */

#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

/* private headers */
#include "pfmlib_priv.h"			/* library private */
#include "pfmlib_arm_priv.h"

const pfmlib_attr_desc_t arm_mods[]={
	PFM_ATTR_B("k", "monitor at kernel level"),
	PFM_ATTR_B("u", "monitor at user level"),
	PFM_ATTR_B("hv", "monitor in hypervisor"),
	PFM_ATTR_NULL /* end-marker to avoid exporting number of entries */
};

pfm_arm_config_t pfm_arm_cfg;

#ifdef CONFIG_PFMLIB_OS_LINUX
/*
 * helper function to retrieve one value from /proc/cpuinfo
 * for internal libpfm use only
 * attr: the attribute (line) to look for
 * ret_buf: a buffer to store the value of the attribute (as a string)
 * maxlen : number of bytes of capacity in ret_buf
 *
 * ret_buf is null terminated.
 *
 * Return:
 * 	0 : attribute found, ret_buf populated
 * 	-1: attribute not found
 */

static int
pfmlib_getcpuinfo_attr(const char *attr, char *ret_buf, size_t maxlen)
{
	FILE *fp = NULL;
	int ret = -1;
	size_t attr_len, buf_len = 0;
	char *p, *value = NULL;
	char *buffer = NULL;

	if (attr == NULL || ret_buf == NULL || maxlen < 1)
		return -1;

	attr_len = strlen(attr);

	fp = fopen("/proc/cpuinfo", "r");
	if (fp == NULL)
		return -1;

	while(pfmlib_getl(&buffer, &buf_len, fp) != -1){

		/* skip  blank lines */
		if (*buffer == '\n')
			continue;

		p = strchr(buffer, ':');
		if (p == NULL)
			goto error;

		/*
		 * p+2: +1 = space, +2= firt character
		 * strlen()-1 gets rid of \n
		 */
		*p = '\0';
		value = p+2;

		value[strlen(value)-1] = '\0';

		if (!strncmp(attr, buffer, attr_len))
			break;
	}
	strncpy(ret_buf, value, maxlen-1);
	ret_buf[maxlen-1] = '\0';
	ret = 0;
error:
	free(buffer);
	fclose(fp);
	return ret;
}
#else
static int
pfmlib_getcpuinfo_attr(const char *attr, char *ret_buf, size_t maxlen)
{
	return -1;
}
#endif

static int
arm_num_mods(void *this, int idx)
{
	const arm_entry_t *pe = this_pe(this);
	unsigned int mask;

	mask = pe[idx].modmsk;
	return pfmlib_popcnt(mask);
}

static inline int
arm_attr2mod(void *this, int pidx, int attr_idx)
{
	const arm_entry_t *pe = this_pe(this);
	size_t x;
	int n;

	n = attr_idx;

	pfmlib_for_each_bit(x, pe[pidx].modmsk) {
		if (n == 0)
			break;
		n--;
	}
	return x;
}

static void
pfm_arm_display_reg(void *this, pfmlib_event_desc_t *e, pfm_arm_reg_t reg)
{
	__pfm_vbprintf("[0x%x] %s\n", reg.val, e->fstr);
}

int
pfm_arm_detect(void *this)
{

	int ret;
	char buffer[128];

	ret = pfmlib_getcpuinfo_attr("CPU implementer", buffer, sizeof(buffer));
	if (ret == -1)
		return PFM_ERR_NOTSUPP;

        pfm_arm_cfg.implementer = strtol(buffer, NULL, 16);
   
   
	ret = pfmlib_getcpuinfo_attr("CPU part", buffer, sizeof(buffer));
	if (ret == -1)
		return PFM_ERR_NOTSUPP;

	pfm_arm_cfg.part = strtol(buffer, NULL, 16);

	ret = pfmlib_getcpuinfo_attr("CPU architecture", buffer, sizeof(buffer));
	if (ret == -1)
		return PFM_ERR_NOTSUPP;

	pfm_arm_cfg.architecture = strtol(buffer, NULL, 16);
   
	return PFM_SUCCESS;
}

int
pfm_arm_get_encoding(void *this, pfmlib_event_desc_t *e)
{

	const arm_entry_t *pe = this_pe(this);
	pfmlib_event_attr_info_t *a;
	pfm_arm_reg_t reg;
	unsigned int plm = 0;
	int i, idx, has_plm = 0;

	reg.val = pe[e->event].code;
  

	for (i = 0; i < e->nattrs; i++) {
		a = attr(e, i);

		if (a->ctrl != PFM_ATTR_CTRL_PMU)
			continue;

		if (a->type > PFM_ATTR_UMASK) {
			uint64_t ival = e->attrs[i].ival;

			switch(a->idx) {
				case ARM_ATTR_U: /* USR */
					if (ival)
						plm |= PFM_PLM3;
					has_plm = 1;
					break;
				case ARM_ATTR_K: /* OS */
					if (ival)
						plm |= PFM_PLM0;
					has_plm = 1;
					break;
				case ARM_ATTR_HV: /* HYPERVISOR */
					if (ival)
						plm |= PFM_PLMH;
					has_plm = 1;
					break;
				default:
					return PFM_ERR_ATTR;
			}
		}
	}

	if (arm_has_plm(this, e)) {
		if (!has_plm)
			plm = e->dfl_plm;
		reg.evtsel.excl_pl1 = !(plm & PFM_PLM0);
		reg.evtsel.excl_usr = !(plm & PFM_PLM3);
		reg.evtsel.excl_hyp = !(plm & PFM_PLMH);
	}

        evt_strcat(e->fstr, "%s", pe[e->event].name);

	e->codes[0] = reg.val;
	e->count    = 1;

	for (i = 0; i < e->npattrs; i++) {
		if (e->pattrs[i].ctrl != PFM_ATTR_CTRL_PMU)
			continue;

		if (e->pattrs[i].type == PFM_ATTR_UMASK)
			continue;

		idx = e->pattrs[i].idx;
		switch(idx) {
		case ARM_ATTR_K:
			evt_strcat(e->fstr, ":%s=%lu", arm_mods[idx].name, !reg.evtsel.excl_pl1);
			break;
		case ARM_ATTR_U:
			evt_strcat(e->fstr, ":%s=%lu", arm_mods[idx].name, !reg.evtsel.excl_usr);
			break;
		case ARM_ATTR_HV:
			evt_strcat(e->fstr, ":%s=%lu", arm_mods[idx].name, !reg.evtsel.excl_hyp);
			break;
		}
	}

        pfm_arm_display_reg(this, e, reg);
   
	return PFM_SUCCESS;
}

int
pfm_arm_get_event_first(void *this)
{
	return 0;
}

int
pfm_arm_get_event_next(void *this, int idx)
{
	pfmlib_pmu_t *p = this;

	if (idx >= (p->pme_count-1))
		return -1;

	return idx+1;
}

int
pfm_arm_event_is_valid(void *this, int pidx)
{
	pfmlib_pmu_t *p = this;
	return pidx >= 0 && pidx < p->pme_count;
}

int
pfm_arm_validate_table(void *this, FILE *fp)
{

	pfmlib_pmu_t *pmu = this;
	const arm_entry_t *pe = this_pe(this);
	int i, j, error = 0;

	for(i=0; i < pmu->pme_count; i++) {
		if (!pe[i].name) {
			fprintf(fp, "pmu: %s event%d: :: no name (prev event was %s)\n", pmu->name, i,
			i > 1 ? pe[i-1].name : "??");
			error++;
		}
		if (!pe[i].desc) {
			fprintf(fp, "pmu: %s event%d: %s :: no description\n", pmu->name, i, pe[i].name);
			error++;
		}
		for(j = i+1; j < pmu->pme_count; j++) {
			if (pe[i].code == pe[j].code && !(pe[j].equiv || pe[i].equiv))  {
				fprintf(fp, "pmu: %s events %s and %s have the same code 0x%x\n", pmu->name, pe[i].name, pe[j].name, pe[i].code);
				error++;
				}
		}
	}
	return error ? PFM_ERR_INVAL : PFM_SUCCESS;
}

int
pfm_arm_get_event_attr_info(void *this, int pidx, int attr_idx, pfmlib_event_attr_info_t *info)
{
	int idx;

	idx = arm_attr2mod(this, pidx, attr_idx);
	info->name = arm_mods[idx].name;
	info->desc = arm_mods[idx].desc;
	info->type = arm_mods[idx].type;
	info->code = idx;

	info->is_dfl = 0;
	info->equiv  = NULL;
	info->ctrl   = PFM_ATTR_CTRL_PMU;
	info->idx    = idx; /* namespace specific index */

	info->dfl_val64  = 0;
	info->is_precise = 0;
	info->support_hw_smpl = 0;

	return PFM_SUCCESS;
}

unsigned int
pfm_arm_get_event_nattrs(void *this, int pidx)
{
	return arm_num_mods(this, pidx);
}

int
pfm_arm_get_event_info(void *this, int idx, pfm_event_info_t *info)
{
	pfmlib_pmu_t *pmu = this;
	const arm_entry_t *pe = this_pe(this);

	info->name  = pe[idx].name;
	info->desc  = pe[idx].desc;
	info->code  = pe[idx].code;
	info->equiv = pe[idx].equiv;
	info->idx   = idx; /* private index */
	info->pmu   = pmu->pmu;
	info->is_precise = 0;
	info->support_hw_smpl = 0;

	/* no attributes defined for ARM yet */
	info->nattrs  = 0;

	return PFM_SUCCESS;
}
