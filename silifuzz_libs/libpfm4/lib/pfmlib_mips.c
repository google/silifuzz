/*
 * pfmlib_mips.c : support for MIPS chips
 *
 * Copyright (c) 2011 Samara Technology Group, Inc
 * Contributed by Philip Mucci <phil.mucci@@samaratechnologygroup.com>
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
#include "pfmlib_mips_priv.h"

pfm_mips_config_t pfm_mips_cfg;

static const pfmlib_attr_desc_t mips_mods[]={
	PFM_ATTR_B("k", "monitor at system level"),
	PFM_ATTR_B("u", "monitor at user level"),
	PFM_ATTR_B("s", "monitor at supervisor level"),
	PFM_ATTR_B("e", "monitor at exception level "),
	PFM_ATTR_NULL /* end-marker to avoid exporting number of entries */
};

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
	DPRINT("/proc/cpuinfo ignored\n");
}
#endif

static void
pfm_mips_display_reg(pfm_mips_sel_reg_t reg, uint64_t cntrs, char *fstr)
{
	__pfm_vbprintf("[0x%"PRIx64" mask=0x%x usr=%d sys=%d sup=%d int=%d cntrs=0x%"PRIx64"] %s\n",
			reg.val,
			reg.perfsel64.sel_event_mask,
			reg.perfsel64.sel_usr,
			reg.perfsel64.sel_os,
			reg.perfsel64.sel_sup,
			reg.perfsel64.sel_exl,
			cntrs,
			fstr);
}

int
pfm_mips_detect(void *this)
{

	int ret;
	char buffer[1024];

	DPRINT("mips_detect\n");

	ret = pfmlib_getcpuinfo_attr("cpu model", buffer, sizeof(buffer));
	if (ret == -1)
		return PFM_ERR_NOTSUPP;

	if (strstr(buffer,"MIPS") == NULL)
	  return PFM_ERR_NOTSUPP;

	strcpy(pfm_mips_cfg.model, buffer);

/*	ret = pfmlib_getcpuinfo_attr("CPU implementer", buffer, sizeof(buffer));
	if (ret == -1)
		return PFM_ERR_NOTSUPP;

	pfm_mips_cfg.implementer = strtol(buffer, NULL, 16);


	ret = pfmlib_getcpuinfo_attr("CPU part", buffer, sizeof(buffer));
	if (ret == -1)
		return PFM_ERR_NOTSUPP;

	pfm_mips_cfg.part = strtol(buffer, NULL, 16);

	ret = pfmlib_getcpuinfo_attr("CPU architecture", buffer, sizeof(buffer));
	if (ret == -1)
		return PFM_ERR_NOTSUPP;

	pfm_mips_cfg.architecture = strtol(buffer, NULL, 16); */

	return PFM_SUCCESS;
}

int
pfm_mips_get_encoding(void *this, pfmlib_event_desc_t *e)
{

	pfmlib_pmu_t *pmu = this;
	const mips_entry_t *pe = this_pe(this);
	pfmlib_event_attr_info_t *a;
	pfm_mips_sel_reg_t reg;
	uint64_t ival, cntmask = 0;
	int plmmsk = 0, code;
	int k, id;

	reg.val = 0;
	code = pe[e->event].code;

	/* truncates bit 7 (counter info) */
	reg.perfsel64.sel_event_mask = code;

	for (k = 0; k < e->nattrs; k++) {
		a = attr(e, k);

		if (a->ctrl != PFM_ATTR_CTRL_PMU)
			continue;

		ival = e->attrs[k].ival;
		switch(a->idx) {
		case MIPS_ATTR_K: /* os */
			reg.perfsel64.sel_os = !!ival;
			plmmsk |= _MIPS_ATTR_K;
			break;
		case MIPS_ATTR_U: /* user */
			reg.perfsel64.sel_usr = !!ival;
			plmmsk |= _MIPS_ATTR_U;
			break;
		case MIPS_ATTR_S: /* supervisor */
			reg.perfsel64.sel_sup = !!ival;
			plmmsk |= _MIPS_ATTR_S;
			break;
		case MIPS_ATTR_E: /* int */
			reg.perfsel64.sel_exl = !!ival;
			plmmsk |= _MIPS_ATTR_E;
		}
	}

	/*
	 * handle case where no priv level mask was passed.
	 * then we use the dfl_plm
	 */
	if (!(plmmsk & MIPS_PLM_ALL)) {
		if (e->dfl_plm & PFM_PLM0)
			reg.perfsel64.sel_os = 1;
		if (e->dfl_plm & PFM_PLM1)
			reg.perfsel64.sel_sup = 1;
		if (e->dfl_plm & PFM_PLM2)
			reg.perfsel64.sel_exl = 1;
		if (e->dfl_plm & PFM_PLM3)
			reg.perfsel64.sel_usr = 1;
	}

        evt_strcat(e->fstr, "%s", pe[e->event].name);

	for (k = 0; k < e->npattrs; k++) {

		if (e->pattrs[k].ctrl != PFM_ATTR_CTRL_PMU)
			continue;

		id = e->pattrs[k].idx;
		switch(id) {
		case MIPS_ATTR_K:
			evt_strcat(e->fstr, ":%s=%lu", mips_mods[id].name, reg.perfsel64.sel_os);
			break;
		case MIPS_ATTR_U:
			evt_strcat(e->fstr, ":%s=%lu", mips_mods[id].name, reg.perfsel64.sel_usr);
			break;
		case MIPS_ATTR_S:
			evt_strcat(e->fstr, ":%s=%lu", mips_mods[id].name, reg.perfsel64.sel_sup);
			break;
		case MIPS_ATTR_E:
			evt_strcat(e->fstr, ":%s=%lu", mips_mods[id].name, reg.perfsel64.sel_exl);
			break;
		}
	}
	e->codes[0] = reg.val;

	/* cycles and instructions support all counters */
	if (code == 0 || code == 1) {
		cntmask = (1ULL << pmu->num_cntrs) -1;
	} else {
		/* event work on odd counters only */
		for (k = !!(code & 0x80) ; k < pmu->num_cntrs; k+=2) {
			cntmask |= 1ULL << k;
		}
	}
	e->codes[1] = cntmask;
	e->count    = 2;

	pfm_mips_display_reg(reg, cntmask, e->fstr);

	return PFM_SUCCESS;
}

int
pfm_mips_get_event_first(void *this)
{
	return 0;
}

int
pfm_mips_get_event_next(void *this, int idx)
{
	pfmlib_pmu_t *p = this;

	if (idx >= (p->pme_count-1))
		return -1;

	return idx+1;
}

int
pfm_mips_event_is_valid(void *this, int pidx)
{
	pfmlib_pmu_t *p = this;
	return pidx >= 0 && pidx < p->pme_count;
}

int
pfm_mips_validate_table(void *this, FILE *fp)
{

	pfmlib_pmu_t *pmu = this;
	const mips_entry_t *pe = this_pe(this);
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
		for (j=i+1; j < pmu->pme_count; j++) {
			if (pe[i].code == pe[j].code) {
				fprintf(fp, "pmu: %s events %s and %s have the same code 0x%x\n", pmu->name, pe[i].name, pe[j].name, pe[i].code);
				error++;
			}
		}
	}
	if (!pmu->supported_plm) {
		fprintf(fp, "pmu: %s supported_plm=0, is that right?\n", pmu->name);
		error++;
	}
	return error ? PFM_ERR_INVAL : PFM_SUCCESS;
}

unsigned int
pfm_mips_get_event_nattrs(void *this, int pidx)
{
	/* assume all pmus have the same number of attributes */
	return MIPS_NUM_ATTRS;
}

int
pfm_mips_get_event_attr_info(void *this, int pidx, int attr_idx, pfmlib_event_attr_info_t *info)
{
	/* no umasks, so all attrs are modifiers */

	info->name = mips_mods[attr_idx].name;
	info->desc = mips_mods[attr_idx].desc;
	info->type = mips_mods[attr_idx].type;
	info->type = mips_mods[attr_idx].type;
	info->equiv= NULL;
	info->idx   = attr_idx; /* private index */
	info->code = attr_idx;
	info->is_dfl = 0;
	info->is_precise = 0;
	info->support_hw_smpl = 0;
	info->ctrl = PFM_ATTR_CTRL_PMU;;

	return PFM_SUCCESS;
}

int
pfm_mips_get_event_info(void *this, int idx, pfm_event_info_t *info)
{
	pfmlib_pmu_t *pmu = this;
	const mips_entry_t *pe = this_pe(this);

	info->name  = pe[idx].name;
	info->desc  = pe[idx].desc;
	info->code  = pe[idx].code;
	info->equiv = NULL;
	info->idx   = idx; /* private index */
	info->pmu   = pmu->pmu;
	info->is_precise = 0;
	info->support_hw_smpl = 0;

	/* no attributes defined for MIPS yet */
	info->nattrs = pfm_mips_get_event_nattrs(this, idx);

	return PFM_SUCCESS;
}
