/*
 * pfmlib_amd64_perf_event.c : perf_event AMD64 functions
 *
 * Copyright (c) 2011 Google, Inc
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
#include <limits.h>

/* private headers */
#include "pfmlib_priv.h"		/* library private */
#include "pfmlib_amd64_priv.h"		/* architecture private */
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
pfm_amd64_get_perf_encoding(void *this, pfmlib_event_desc_t *e)
{
	pfmlib_pmu_t *pmu = this;
	pfm_amd64_reg_t reg;
	struct perf_event_attr *attr = e->os_data;
	int ret;

	if (!pmu->get_event_encoding[PFM_OS_NONE])
		return PFM_ERR_NOTSUPP;

	/*
	 * use generic raw encoding function first
	 */
	ret = pmu->get_event_encoding[PFM_OS_NONE](this, e);
	if (ret != PFM_SUCCESS)
		return ret;

	if (e->count > 1) {
		DPRINT("unsupported count=%d\n", e->count);
		return PFM_ERR_NOTSUPP;
	}

	ret = PERF_TYPE_RAW;

	/*
	 * if specific perf PMU is provided then try to locate it
	 * otherwise assume core PMU and thus type RAW
	 */
	if (pmu->perf_name) {
		/* greab PMU type from sysfs */
		ret = find_pmu_type_by_name(pmu->perf_name);
		if (ret < 0)
			return ret;
	}
	DPRINT("amd64_get_perf_encoding: PMU type=%d\n", ret);
	attr->type = ret;

	reg.val = e->codes[0];
	/*
	 * suppress the bits which are under the control of perf_events
	 * they will be ignore by the perf tool and the kernel interface
	 * the OS/USR bits are controlled by the attr.exclude_* fields
	 * the EN/INT bits are controlled by the kernel
	 */
	reg.sel_en    = 0;
	reg.sel_int   = 0;
	reg.sel_os    = 0;
	reg.sel_usr   = 0;
	reg.sel_guest = 0;
	reg.sel_host  = 0;

	attr->config = reg.val;

	return PFM_SUCCESS;
}

void
pfm_amd64_perf_validate_pattrs(void *this, pfmlib_event_desc_t *e)
{
	pfmlib_pmu_t *pmu = this;

	int i, compact;

	for (i=0; i < e->npattrs; i++) {
		compact = 0;

		/* umasks never conflict */
		if (e->pattrs[i].type == PFM_ATTR_UMASK)
			continue;

		/*
		 * with perf_events, u and k are handled at the OS level
		 * via attr.exclude_* fields
		 */
		if (e->pattrs[i].ctrl == PFM_ATTR_CTRL_PMU) {

			if (e->pattrs[i].idx == AMD64_ATTR_U
			    || e->pattrs[i].idx == AMD64_ATTR_K
			    || e->pattrs[i].idx == AMD64_ATTR_H)
				compact = 1;
		}

		if (e->pattrs[i].ctrl == PFM_ATTR_CTRL_PERF_EVENT) {

			/* No precise mode on AMD */
			if (e->pattrs[i].idx == PERF_ATTR_PR)
				compact = 1;

			/* older processors do not support hypervisor priv level */
			if (e->pattrs[i].idx == PERF_ATTR_H &&!pfm_amd64_supports_virt(pmu))
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

void
pfm_amd64_nb_perf_validate_pattrs(void *this, pfmlib_event_desc_t *e)
{
	int i, compact;

	for (i=0; i < e->npattrs; i++) {
		compact = 0;

		/* umasks never conflict */
		if (e->pattrs[i].type == PFM_ATTR_UMASK)
			continue;

		/*
		 * no perf_events attr is supported by AMD64 Northbridge PMU
		 * sampling is not supported
		 */
		if (e->pattrs[i].ctrl == PFM_ATTR_CTRL_PERF_EVENT) {
			compact = 1;
		}

		/* hardware sampling not supported on AMD */
		if (e->pattrs[i].idx == PERF_ATTR_HWS)
			compact = 1;


		if (compact) {
			pfmlib_compact_pattrs(e, i);
			i--;
		}
	}
}
