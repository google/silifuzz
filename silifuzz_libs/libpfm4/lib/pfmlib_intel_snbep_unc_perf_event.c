/* pfmlib_intel_snbep_unc_perf.c : perf_events SNB-EP uncore support
 *
 * Copyright (c) 2012 Google, Inc
 * Contributed by Stephane Eranian <eranian@gmail.com>
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
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <limits.h>

/* private headers */
#include "pfmlib_priv.h"
#include "pfmlib_intel_x86_priv.h"
#include "pfmlib_intel_snbep_unc_priv.h"
#include "pfmlib_perf_event_priv.h"

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
pfm_intel_snbep_unc_get_perf_encoding(void *this, pfmlib_event_desc_t *e)
{
	pfmlib_pmu_t *pmu = this;
	struct perf_event_attr *attr = e->os_data;
	pfm_snbep_unc_reg_t reg;
	int ret;

	if (!pmu->get_event_encoding[PFM_OS_NONE])
		return PFM_ERR_NOTSUPP;

	ret = pmu->get_event_encoding[PFM_OS_NONE](this, e);
	if (ret != PFM_SUCCESS)
		return ret;

	ret = find_pmu_type_by_name(pmu->perf_name);
	if (ret < 0)
		return ret;

	attr->type = ret;

	reg.val = e->codes[0];

	attr->config = reg.val;

	if (( is_cbo_filt_event(this, reg)
	   || is_cha_filt_event(this, 0, reg)
	   || is_cha_filt_event(this, 1, reg))
	    && e->count > 1) {
		if (e->count >= 2)
			attr->config1 = e->codes[1];
		if (e->count >= 3)
			attr->config1 |= e->codes[2] << 32;
	} else {
		/*
		 * various filters
		 */
		if (e->count >= 2)
			attr->config1 = e->codes[1];

		if (e->count >= 3)
			attr->config2 = e->codes[2];
	}

	/*
	 * uncore measures at all priv levels
	 *
	 * user cannot set per-event priv levels because
	 * attributes are simply not there
	 *
	 * dfl_plm is ignored in this case
	 */
	attr->exclude_hv = 0;
	attr->exclude_kernel = 0;
	attr->exclude_user = 0;

	return PFM_SUCCESS;
}

void
pfm_intel_snbep_unc_perf_validate_pattrs(void *this, pfmlib_event_desc_t *e)
{
	pfmlib_pmu_t *pmu = this;
	int no_smpl = pmu->flags & PFMLIB_PMU_FL_NO_SMPL;
	int i, compact;

	for (i = 0; i < e->npattrs; i++) {
		compact = 0;
		/* umasks never conflict */
		if (e->pattrs[i].type == PFM_ATTR_UMASK)
			continue;

		if (e->pattrs[i].ctrl == PFM_ATTR_CTRL_PERF_EVENT) {

			/* No precise sampling mode for uncore */
			if (e->pattrs[i].idx == PERF_ATTR_PR)
				compact = 1;

			/*
			 * No hypervisor for uncore
			 */
			if (e->pattrs[i].idx == PERF_ATTR_H)
				compact = 1;

			if (no_smpl
			    && (   e->pattrs[i].idx == PERF_ATTR_FR
			        || e->pattrs[i].idx == PERF_ATTR_PR
			        || e->pattrs[i].idx == PERF_ATTR_PE))
				compact = 1;

			/*
			 * uncore has no priv level support
			 */
			if (pmu->supported_plm == 0
			    && (   e->pattrs[i].idx == PERF_ATTR_U
			        || e->pattrs[i].idx == PERF_ATTR_K
			        || e->pattrs[i].idx == PERF_ATTR_MG
			        || e->pattrs[i].idx == PERF_ATTR_MH))
				compact = 1;
		}

		/* hardware sampling not supported */
		if (e->pattrs[i].idx == PERF_ATTR_HWS)
			compact = 1;

		if (compact) {
			pfmlib_compact_pattrs(e, i);
			i--;
		}
	}
}
