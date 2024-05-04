/*
 * pfmlib_powerpc_perf_event.c : perf_event IBM Power/Torrent functions
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
#include "pfmlib_power_priv.h"		/* architecture private */
#include "pfmlib_perf_event_priv.h"

int
pfm_gen_powerpc_get_perf_encoding(void *this, pfmlib_event_desc_t *e)
{
	pfmlib_pmu_t *pmu = this;
	struct perf_event_attr *attr = e->os_data;
	int ret;

	if (!pmu->get_event_encoding[PFM_OS_NONE])
		return PFM_ERR_NOTSUPP;

	/*
	 * encoding routine changes based on PMU model
	 */
	ret = pmu->get_event_encoding[PFM_OS_NONE](this, e);
	if (ret != PFM_SUCCESS)
		return ret;

	attr->type = PERF_TYPE_RAW;
	attr->config = e->codes[0];

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
pfm_gen_powerpc_get_nest_perf_encoding(void *this, pfmlib_event_desc_t *e)
{
    pfmlib_pmu_t *pmu = this;
    struct perf_event_attr *attr = e->os_data;
    int ret;

    if (!pmu->get_event_encoding[PFM_OS_NONE])
        return PFM_ERR_NOTSUPP;

    /*
     * encoding routine changes based on PMU model
     */
    ret = pmu->get_event_encoding[PFM_OS_NONE](this, e);
    if (ret != PFM_SUCCESS)
         return ret;

    ret = find_pmu_type_by_name(pmu->perf_name);
    if (ret < 0)
        return ret;

    attr->type = ret;
    attr->config = e->codes[0];

    return PFM_SUCCESS;
}


void
pfm_gen_powerpc_perf_validate_pattrs(void *this, pfmlib_event_desc_t *e)
{
	int i, compact;

	for (i = 0; i < e->npattrs; i++) {
		compact = 0;

		/* umasks never conflict */
		if (e->pattrs[i].type == PFM_ATTR_UMASK)
			continue;

		/*
		 * remove PMU-provided attributes which are either
		 * not accessible under perf_events or fully controlled
		 * by perf_events, e.g., priv levels filters
		 */
		if (e->pattrs[i].ctrl == PFM_ATTR_CTRL_PMU) {
		}

		/*
		 * remove perf_event generic attributes not supported
		 * by PPC
		 */
		if (e->pattrs[i].ctrl == PFM_ATTR_CTRL_PERF_EVENT) {
			/* no precise sampling */
			if (e->pattrs[i].idx == PERF_ATTR_PR)
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
