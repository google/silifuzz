/* pfmlib_intel_netburst_perf_event.c : perf_event Intel Netburst functions
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
 *
 * This file implements the common code for all Intel X86 processors.
 */
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

/* private headers */
#include "pfmlib_priv.h"
#include "pfmlib_intel_netburst_priv.h"
#include "pfmlib_perf_event_priv.h"

int
pfm_netburst_get_perf_encoding(void *this, pfmlib_event_desc_t *e)
{
	const netburst_entry_t *pe = this_pe(this);
	struct perf_event_attr *attr = e->os_data;
	int perf_code = pe[e->event].perf_code;
	uint64_t escr;
	int ret;

	ret = pfm_netburst_get_encoding(this, e);
	if (ret != PFM_SUCCESS)
		return ret;


	attr->type = PERF_TYPE_RAW;
	/*
	 * codes[0] = ESCR
	 * codes[1] = CCCR
	 *
	 * cleanup event_select, and install perf specific code
	 */
	escr  = e->codes[0] & ~(0x3full << 25);
	escr |= perf_code << 25;
	attr->config = (escr << 32) | e->codes[1];

	return PFM_SUCCESS;
}

void
pfm_netburst_perf_validate_pattrs(void *this, pfmlib_event_desc_t *e)
{
	int i, compact;

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
			if (e->pattrs[i].idx == NETBURST_ATTR_U
					|| e->pattrs[i].idx == NETBURST_ATTR_K)
				compact = 1;
		}
		if (e->pattrs[i].ctrl == PFM_ATTR_CTRL_PERF_EVENT) {

			/* no PEBS support (for now) */
			if (e->pattrs[i].idx == PERF_ATTR_PR)
				compact = 1;
			/*
			 * No hypervisor on Intel */
			if (e->pattrs[i].idx == PERF_ATTR_H)
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
