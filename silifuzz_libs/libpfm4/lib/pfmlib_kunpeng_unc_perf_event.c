/*
 * Copyright (c) 2021 Barcelona Supercomputing Center
 * Contributed by Estanislao Mercadal Melià <lau.mercadal@bsc.es>
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
#include <limits.h>

/* private headers */
#include "pfmlib_priv.h"
#include "pfmlib_perf_event_priv.h"
#include "pfmlib_arm_priv.h"

typedef struct {
	uint64_t val;
} kunpeng_unc_data_t;

static void
display_com(void *this, pfmlib_event_desc_t *e, void *val)
{
	const arm_entry_t *pe = this_pe(this);
	kunpeng_unc_data_t *reg = val;

	__pfm_vbprintf("[UNC=0x%"PRIx64"] %s\n",
			reg->val,
			pe[e->event].name);
}

static void
display_reg(void *this, pfmlib_event_desc_t *e, kunpeng_unc_data_t reg)
{
	pfmlib_pmu_t *pmu = this;
	if (pmu->display_reg)
		pmu->display_reg(this, e, &reg);
	else
		display_com(this, e, &reg);
}

int
pfm_kunpeng_unc_get_event_encoding(void *this, pfmlib_event_desc_t *e)
{
	//from pe field in for the uncore, get the array with all the event defs
	const arm_entry_t *event_list = this_pe(this);
	kunpeng_unc_data_t reg;
	//get code for the event from the table
	reg.val = event_list[e->event].code;
	//pass the data back to the caller
	e->codes[0] = reg.val;
	e->count = 1;
	evt_strcat(e->fstr, "%s", event_list[e->event].name);
	display_reg(this, e, reg);
	return PFM_SUCCESS;
}

static int
find_pmu_type_by_name(const char *name)
{
	char filename[PATH_MAX];
	FILE *fp;
	int ret, type;

	if (!name)
		return PFM_ERR_NOTSUPP;

	sprintf(filename, "/sys/bus/event_source/devices/%s/type", name);

	fp = fopen(filename, "r");
	if (!fp)
		return PFM_ERR_NOTSUPP;

	ret = fscanf(fp, "%d", &type);
	if (ret != 1)
		type = PFM_ERR_NOTSUPP;

	fclose(fp);

	return type;
}

int
pfm_kunpeng_unc_get_perf_encoding(void *this, pfmlib_event_desc_t *e)
{
	pfmlib_pmu_t *pmu = this;
	struct perf_event_attr *attr = e->os_data;
	kunpeng_unc_data_t reg;
	int ret;

	if (!pmu->get_event_encoding[PFM_OS_NONE])
		return PFM_ERR_NOTSUPP;

	ret = pmu->get_event_encoding[PFM_OS_NONE](this, e);
	if (ret != PFM_SUCCESS)
		return ret;
	//get pmu type to probe
	ret = find_pmu_type_by_name(pmu->perf_name);
	if (ret < 0)
		return ret;

	attr->type = ret;
	//get code to provide to the uncore pmu probe
	reg.val = e->codes[0];
	attr->config = reg.val;

	// if needed, can use attr->config1 or attr->config2 for extra info from event structure defines e->codes[i]

	// uncore measures at all priv levels
	attr->exclude_hv = 0;
	attr->exclude_kernel = 0;
	attr->exclude_user = 0;

	return PFM_SUCCESS;
}
