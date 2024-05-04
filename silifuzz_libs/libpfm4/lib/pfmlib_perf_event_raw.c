/*
 * pfmlib_perf_events_raw.c: support for raw event syntax
 *
 * Copyright (c) 2014 Google, Inc. All rights reserved
 * Contributed by Stephane Eranian <eranian@google.com>
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
#include <unistd.h>
#include <ctype.h>
#include <limits.h>
#include <errno.h>

#include "pfmlib_priv.h"
#include "pfmlib_perf_event_priv.h"

static int
pfm_perf_raw_detect(void *this)
{
#ifdef __linux__
	/* ought to find a better way of detecting PERF */
#define PERF_OLD_PROC_FILE "/proc/sys/kernel/perf_counter_paranoid"
#define PERF_PROC_FILE "/proc/sys/kernel/perf_event_paranoid"
	return !(access(PERF_PROC_FILE, F_OK)
		  && access(PERF_OLD_PROC_FILE, F_OK)) ? PFM_SUCCESS: PFM_ERR_NOTSUPP;
#else
	return PFM_SUCCESS;
#endif
}

static int
pfm_perf_raw_get_event_first(void *this)
{
	return 0;
}

static int
pfm_perf_raw_get_event_next(void *this, int idx)
{
	/* only one pseudo event */
	return -1;
}

static int
pfm_perf_raw_get_encoding(void *this, pfmlib_event_desc_t *e)
{
	/*
	 * actual enoding done in pfm_perf_raw_match_event()
	 */
	e->fstr[0] = '\0';
	evt_strcat(e->fstr, "r%"PRIx64, e->codes[0]);
	return PFM_SUCCESS;
}

static int
pfm_perf_raw_get_perf_encoding(void *this, pfmlib_event_desc_t *e)
{
	struct perf_event_attr *attr;

	attr = e->os_data;
	attr->type = PERF_TYPE_RAW;
	attr->config = e->codes[0];

	attr->config1 = e->codes[1];
	attr->config2 = e->codes[2];

	return PFM_SUCCESS;
}

static int
pfm_perf_raw_event_is_valid(void *this, int idx)
{
	return idx == 0;
}

static int
pfm_perf_raw_get_event_attr_info(void *this, int idx, int attr_idx, pfmlib_event_attr_info_t *info)
{
	return PFM_ERR_ATTR;
}

static int
pfm_perf_raw_get_event_info(void *this, int idx, pfm_event_info_t *info)
{
	pfmlib_pmu_t *pmu = this;

	info->name  = "r0000";
	info->desc  = "perf_events raw event syntax: r[0-9a-fA-F]+",
	info->code  = 0;
	info->equiv = NULL;
	info->idx   = 0;
	info->pmu   = pmu->pmu;
	info->is_precise = 0;
	info->support_hw_smpl = 0;

	/* unit masks + modifiers */
	info->nattrs  = 0;

	return PFM_SUCCESS;
}

static unsigned int
pfm_perf_raw_get_event_nattrs(void *this, int idx)
{
	return 0;
}

/*
 * remove attrs which are in conflicts (or duplicated) with os layer
 */
static void
pfm_perf_raw_perf_validate_pattrs(void *this, pfmlib_event_desc_t *e)
{
}

/*
 * returns 0 if match (like strcmp())
 */
static int
pfm_perf_raw_match_event(void *this, pfmlib_event_desc_t *d, const char *e, const char *s)
{
	uint64_t code;
	char *endptr = NULL;

	if (*s != 'r'  || !isxdigit(*(s+1)))
		return 1;

	code = strtoull(s+1, &endptr, 16);
	if (code == ULLONG_MAX || errno == ERANGE|| (endptr && *endptr))
		return 1;

	/*
	 * stash code in final position
	 */
	d->codes[0] = code;
	d->count = 1;

	return 0;
}

pfmlib_pmu_t perf_event_raw_support={
	.desc			= "perf_events raw PMU",
	.name			= "perf_raw",
	.pmu			= PFM_PMU_PERF_EVENT_RAW,
	.pme_count		= 1,
	.type			= PFM_PMU_TYPE_OS_GENERIC,
	.max_encoding		= 1,
	.supported_plm		= PERF_PLM_ALL,
	.pmu_detect		= pfm_perf_raw_detect,
	.get_event_encoding[PFM_OS_NONE] = pfm_perf_raw_get_encoding,
	 PFMLIB_ENCODE_PERF(pfm_perf_raw_get_perf_encoding),
	.get_event_first	= pfm_perf_raw_get_event_first,
	.get_event_next		= pfm_perf_raw_get_event_next,
	.event_is_valid		= pfm_perf_raw_event_is_valid,
	.get_event_info		= pfm_perf_raw_get_event_info,
	.get_event_attr_info	= pfm_perf_raw_get_event_attr_info,
	.get_event_nattrs	= pfm_perf_raw_get_event_nattrs,
	.match_event		= pfm_perf_raw_match_event,
	 PFMLIB_VALID_PERF_PATTRS(pfm_perf_raw_perf_validate_pattrs),
};
