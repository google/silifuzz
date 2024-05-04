/*
 * pfmlib_sparc.c : support for SPARC processors
 * 
 * Copyright (c) 2011 Google, Inc
 * Contributed by Stephane Eranian <eranian@gmail.com>
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
 */
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

/* private headers */
#include "pfmlib_priv.h"			/* library private */
#include "pfmlib_sparc_priv.h"

const pfmlib_attr_desc_t sparc_mods[]={
	PFM_ATTR_B("k", "monitor at priv level 0"),		/* monitor priv level 0 */
	PFM_ATTR_B("u", "monitor at priv level 1, 2, 3"),	/* monitor priv level 1, 2, 3 */
	PFM_ATTR_B("h", "monitor in hypervisor"),		/* monitor in hypervisor*/
	PFM_ATTR_NULL /* end-marker to avoid exporting number of entries */
};
#define SPARC_NUM_MODS (sizeof(sparc_mods)/sizeof(pfmlib_attr_desc_t) - 1)

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

static pfm_pmu_t
pmu_name_to_pmu_type(char *name)
{
	if (!strcmp(name, "ultra12"))
		return PFM_PMU_SPARC_ULTRA12;
	if (!strcmp(name, "ultra3"))
		return PFM_PMU_SPARC_ULTRA3;
	if (!strcmp(name, "ultra3i"))
		return PFM_PMU_SPARC_ULTRA3I;
	if (!strcmp(name, "ultra3+"))
		return PFM_PMU_SPARC_ULTRA3PLUS;
	if (!strcmp(name, "ultra4+"))
		return PFM_PMU_SPARC_ULTRA4PLUS;
	if (!strcmp(name, "niagara2"))
		return PFM_PMU_SPARC_NIAGARA2;
	if (!strcmp(name, "niagara"))
		return PFM_PMU_SPARC_NIAGARA1;
	return PFM_PMU_NONE;
}

int
pfm_sparc_detect(void *this)
{
	pfmlib_pmu_t *pmu = this;
	pfm_pmu_t model;
	int ret;
	char buffer[32];

	ret = pfmlib_getcpuinfo_attr("pmu", buffer, sizeof(buffer));
	if (ret == -1)
		return PFM_ERR_NOTSUPP;

	model = pmu_name_to_pmu_type(buffer);
	
	return model == pmu->pmu ? PFM_SUCCESS : PFM_ERR_NOTSUPP;
}

void
pfm_sparc_display_reg(void *this, pfmlib_event_desc_t *e, pfm_sparc_reg_t reg)
{
	__pfm_vbprintf("[0x%x umask=0x%x code=0x%x ctrl_s1=%d ctrl_s0=%d] %s\n",
		reg.val,
		reg.config.umask,
		reg.config.code,
		reg.config.ctrl_s1,
		reg.config.ctrl_s0,
		e->fstr);
}

int
pfm_sparc_get_encoding(void *this, pfmlib_event_desc_t *e)
{
	const sparc_entry_t *pe = this_pe(this);
	pfmlib_event_attr_info_t *a;
	pfm_sparc_reg_t reg;
	int i;


	//reg.val = pe[e->event].code << 16 | pe[e->event].ctrl;
	reg.val = pe[e->event].code;

	for (i = 0; i < e->nattrs; i++) {

		a = attr(e, i);

		if (a->ctrl != PFM_ATTR_CTRL_PMU)
			continue;

		if (a->type == PFM_ATTR_UMASK)
			reg.config.umask |= 1 << pe[e->event].umasks[a->idx].ubit;
	}

	e->count = 2;
	e->codes[0] = reg.val;
	e->codes[1] = pe[e->event].ctrl;

	evt_strcat(e->fstr, "%s", pe[e->event].name);

	pfmlib_sort_attr(e);
	for (i = 0; i < e->nattrs; i++) {

		a = attr(e, i);

		if (a->ctrl != PFM_ATTR_CTRL_PMU)
			continue;

		if (a->type == PFM_ATTR_UMASK)
			evt_strcat(e->fstr, ":%s", pe[e->event].umasks[a->idx].uname);
	}

	pfm_sparc_display_reg(this, e, reg);

	return PFM_SUCCESS;
}

int
pfm_sparc_get_event_first(void *this)
{
	return 0;
}

int
pfm_sparc_get_event_next(void *this, int idx)
{
	pfmlib_pmu_t *p = this;

	if (idx >= (p->pme_count-1))
		return -1;

	return idx+1;
}

int
pfm_sparc_event_is_valid(void *this, int pidx)
{
	pfmlib_pmu_t *p = this;
	return pidx >= 0 && pidx < p->pme_count;
}

int
pfm_sparc_validate_table(void *this, FILE *fp)
{

	pfmlib_pmu_t *pmu = this;
	const sparc_entry_t *pe = this_pe(this);
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
		for(j=i+1; j < pmu->pme_count; j++) {
			if (pe[i].code == pe[j].code && pe[i].ctrl == pe[j].ctrl) {
				fprintf(fp, "pmu: %s event%d: %s code: 0x%x is duplicated in event%d : %s\n", pmu->name, i, pe[i].name, pe[i].code, j, pe[j].name);
				error++;
			}
		}
	}
	return error ? PFM_ERR_INVAL : PFM_SUCCESS;
}

int
pfm_sparc_get_event_attr_info(void *this, int pidx, int attr_idx, pfmlib_event_attr_info_t *info)
{
	const sparc_entry_t *pe = this_pe(this);
	int idx;

	if (attr_idx < pe[pidx].numasks) {
		info->name = pe[pidx].umasks[attr_idx].uname;
		info->desc = pe[pidx].umasks[attr_idx].udesc;
		info->name = pe[pidx].umasks[attr_idx].uname;
		info->equiv= NULL;
		info->code = 1 << pe[pidx].umasks[attr_idx].ubit;
		info->type = PFM_ATTR_UMASK;
		info->idx = attr_idx;
	} else {
		/*
		 * all mods implemented by ALL events */
		idx = attr_idx - pe[pidx].numasks;

		info->name = sparc_mods[idx].name;
		info->desc = sparc_mods[idx].desc;
		info->type = sparc_mods[idx].type;
		info->code = idx;

		info->type = sparc_mods[idx].type;
	}

	info->is_dfl = 0;
	info->is_precise = 0;
	info->support_hw_smpl = 0;
	info->ctrl = PFM_ATTR_CTRL_PMU;;

	return PFM_SUCCESS;
}

int
pfm_sparc_get_event_info(void *this, int idx, pfm_event_info_t *info)
{
	pfmlib_pmu_t *pmu = this;
	const sparc_entry_t *pe = this_pe(this);
	/*
	 * pmu and idx filled out by caller
	 */
	info->name  = pe[idx].name;
	info->desc  = pe[idx].desc;
	info->code  = pe[idx].code;
	info->equiv = NULL;
	info->idx   = idx; /* private index */
	info->pmu   = pmu->pmu;
	info->is_precise = 0;
	info->support_hw_smpl = 0;

	info->nattrs  = pe[idx].numasks;

	return PFM_SUCCESS;
}

unsigned int
pfm_sparc_get_event_nattrs(void *this, int pidx)
{
	const sparc_entry_t *pe = this_pe(this);

	return SPARC_NUM_MODS + pe[pidx].numasks;
}
