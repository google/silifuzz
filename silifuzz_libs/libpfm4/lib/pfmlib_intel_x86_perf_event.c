/* pfmlib_intel_x86_perf.c : perf_event Intel X86 functions
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
#include <stdio.h>
#include <stdarg.h>
#include <limits.h>

/* private headers */
#include "pfmlib_priv.h"
#include "pfmlib_intel_x86_priv.h"
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

static int
has_ldlat(void *this, pfmlib_event_desc_t *e)
{
	pfmlib_event_attr_info_t *a;
	int i;

	for (i = 0; i < e->nattrs; i++) {
		a = attr(e, i);

		if (a->ctrl != PFM_ATTR_CTRL_PMU)
			continue;

		if (a->type != PFM_ATTR_UMASK)
			continue;

		if (intel_x86_uflag(this, e->event, a->idx, INTEL_X86_LDLAT))
			return 1;
	}
	return 0;
}

int
pfm_intel_x86_get_perf_encoding(void *this, pfmlib_event_desc_t *e)
{
	pfmlib_pmu_t *pmu = this;
	pfm_intel_x86_reg_t reg;
	struct perf_event_attr *attr = e->os_data;
	int ret;

	if (!pmu->get_event_encoding[PFM_OS_NONE])
		return PFM_ERR_NOTSUPP;

	/*
	 * first, we need to do the generic encoding
	 */
	ret = pmu->get_event_encoding[PFM_OS_NONE](this, e);
	if (ret != PFM_SUCCESS)
		return ret;

	if (e->count > 2) {
		DPRINT("unsupported count=%d\n", e->count);
		return PFM_ERR_NOTSUPP;
	}
	/* default PMU type */
	attr->type = PERF_TYPE_RAW;

	/*
	 * if PMU specifies a perf PMU name, then grab the type
	 * from sysfs as it is most likely dynamically assigned.
	 * This allows this function to use used by some uncore PMUs
	 */
	if (pmu->perf_name) {
		int type = find_pmu_type_by_name(pmu->perf_name);
		if (type == PFM_ERR_NOTSUPP) {
			DPRINT("perf PMU %s, not supported by OS\n", pmu->perf_name);
		} else {
			DPRINT("PMU %s perf type=%d\n", pmu->name, type);
			attr->type = type;
		}
	}

	reg.val = e->codes[0];

	/*
	 * suppress the bits which are under the control of perf_events
	 * they will be ignore by the perf tool and the kernel interface
	 * the OS/USR bits are controlled by the attr.exclude_* fields
	 * the EN/INT bits are controlled by the kernel
	 */
	reg.sel_en   = 0;
	reg.sel_int  = 0;
	reg.sel_os   = 0;
	reg.sel_usr  = 0;

	attr->config = reg.val;

	if (e->count > 1) {
		/*
		 * Nehalem/Westmere/Sandy Bridge OFFCORE_RESPONSE events
		 * take two MSRs. Lower level returns two codes:
		 * - codes[0] goes to regular counter config
		 * - codes[1] goes into extra MSR
		 */
		if (intel_x86_eflag(this, e->event, INTEL_X86_NHM_OFFCORE)) {
			if (e->count != 2) {
				DPRINT("perf_encoding: offcore=1 count=%d\n", e->count);
				return PFM_ERR_INVAL;
			}
			attr->config1 = e->codes[1];
		}
		/*
		 * SkyLake FRONTEND_RETIRED event
		 * takes two MSRs. Lower level returns two codes:
		 * - codes[0] goes to regular counter config
		 * - codes[1] goes into extra MSR
		 */
		if (intel_x86_eflag(this, e->event, INTEL_X86_FRONTEND)) {
			if (e->count != 2) {
				DPRINT("perf_encoding: frontend_retired=1 count=%d\n", e->count);
				return PFM_ERR_INVAL;
			}
			attr->config1 = e->codes[1];
		}

		/*
		 * Event has filters and perf_events expects them in the umask (extended)
		 * For instance: SK UPI BASIC_HDR_FILT
		 */
		if (e->count > 1 && intel_x86_eflag(this, e->event, INTEL_X86_FILT_UMASK)) {
			attr->config |= e->codes[1] << 32;
		}

		/*
		 * Load Latency threshold (NHM/WSM/SNB)
		 * - codes[0] goes to regular counter config
		 * - codes[1] LD_LAT MSR value (LSB 16 bits)
		 */
		if (has_ldlat(this, e)) {
			if (e->count != 2) {
				DPRINT("perf_encoding: ldlat count=%d\n", e->count);
				return PFM_ERR_INVAL;
			}
			attr->config1 = e->codes[1];
		}
	}
	return PFM_SUCCESS;
}

int
pfm_intel_nhm_unc_get_perf_encoding(void *this, pfmlib_event_desc_t *e)
{
	pfmlib_pmu_t *pmu = this;
	struct perf_event_attr *attr = e->os_data;
	pfm_intel_x86_reg_t reg;
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

	/*
	 * encoder treats all events as using the generic
	 * counters.
	 * perf_events override the enable and int bits, so
	 * drop them here.
	 *
	 * also makes fixed counter special encoding 0xff
	 * work. kernel checking for perfect match.
	 */
	reg.nhm_unc.usel_en  = 0;
	reg.nhm_unc.usel_int = 0;

	attr->config = reg.val;

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

int
pfm_intel_x86_requesting_pebs(pfmlib_event_desc_t *e)
{
	pfmlib_event_attr_info_t *a;
	int i;

	for (i = 0; i < e->nattrs; i++) {
		a = attr(e, i);
		if (a->ctrl != PFM_ATTR_CTRL_PERF_EVENT)
			continue;
		if (a->idx == PERF_ATTR_PR && e->attrs[i].ival)
			return 1;
	}
	return 0;
}

static int
intel_x86_event_has_pebs(void *this, pfmlib_event_desc_t *e)
{
	pfmlib_event_attr_info_t *a;
	int i;

	/* first check at the event level */
	if (intel_x86_eflag(e->pmu, e->event, INTEL_X86_PEBS))
		return 1;

	/* check umasks */
	for(i=0; i < e->npattrs; i++) {
		a = e->pattrs+i;

		if (a->ctrl != PFM_ATTR_CTRL_PMU || a->type != PFM_ATTR_UMASK)
			continue;

		if (intel_x86_uflag(e->pmu, e->event, a->idx, INTEL_X86_PEBS))
			return 1;
	}
	return 0;
}

static int
intel_x86_event_has_hws(void *this, pfmlib_event_desc_t *e)
{
	pfmlib_pmu_t *pmu = this;
	return !!(pmu->flags & INTEL_X86_PMU_FL_EXTPEBS);
}

/*
 * remove attrs which are in conflicts (or duplicated) with os layer
 */
void
pfm_intel_x86_perf_validate_pattrs(void *this, pfmlib_event_desc_t *e)
{
	pfmlib_pmu_t *pmu = this;
	int i, compact;
	int has_hws = intel_x86_event_has_hws(this, e);
	int has_pebs = intel_x86_event_has_pebs(this, e);
	int no_smpl = pmu->flags & PFMLIB_PMU_FL_NO_SMPL;

	for (i = 0; i < e->npattrs; i++) {
		compact = 0;
		/* umasks never conflict */
		if (e->pattrs[i].type == PFM_ATTR_UMASK)
			continue;

		/*
		 * with perf_events, u and k are handled at the OS level
		 * via exclude_user, exclude_kernel.
		 */
		if (e->pattrs[i].ctrl == PFM_ATTR_CTRL_PMU) {
			if (e->pattrs[i].idx == INTEL_X86_ATTR_U
			    || e->pattrs[i].idx == INTEL_X86_ATTR_K)
				compact = 1;
		}
		if (e->pattrs[i].ctrl == PFM_ATTR_CTRL_PERF_EVENT) {

			/* Precise mode, subject to PEBS */
			if (e->pattrs[i].idx == PERF_ATTR_PR && !has_pebs)
				compact = 1;

			/* hardware sampling mode, subject to HWS or PEBS */
			if (e->pattrs[i].idx == PERF_ATTR_HWS && (!has_hws || has_pebs))
				compact = 1;

			/*
			 * No hypervisor on Intel
			 */
			if (e->pattrs[i].idx == PERF_ATTR_H)
				compact = 1;

			if (no_smpl
			    && (   e->pattrs[i].idx == PERF_ATTR_FR
			        || e->pattrs[i].idx == PERF_ATTR_PR
			        || e->pattrs[i].idx == PERF_ATTR_PE))
				compact = 1;
			/*
			 * no priv level support
			 * We assume that if we do not support hardware plm,
			 * then the host, guest priv level filtering in not
			 * supported as well, even though on some arch it is
			 * achieved by the OS enabling/disabled on VMM entry
			 * and exit.
			 */
			if (pmu->supported_plm == 0
			    && (   e->pattrs[i].idx == PERF_ATTR_U
			        || e->pattrs[i].idx == PERF_ATTR_K
			        || e->pattrs[i].idx == PERF_ATTR_MG
			        || e->pattrs[i].idx == PERF_ATTR_MH))
				compact = 1;
		}

		if (compact) {
			/* e->npattrs modified by call */
			pfmlib_compact_pattrs(e, i);
			/* compensate for i++ */
			i--;
		}
	}
}

int
pfm_intel_x86_perf_detect(void *this)
{
	pfmlib_pmu_t *pmu = this;
	char file[64];

	snprintf(file,sizeof(file), "/sys/devices/%s", pmu->perf_name);
	return access(file, R_OK|X_OK) ? PFM_ERR_NOTSUPP : PFM_SUCCESS;
}
