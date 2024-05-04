/*
 * pfmlib_mips_perf_event.c : perf_event MIPS functions
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
 */
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>

#include "pfmlib_priv.h"
#include "pfmlib_mips_priv.h"
#include "pfmlib_perf_event_priv.h"

int
pfm_mips_get_perf_encoding(void *this, pfmlib_event_desc_t *e)
{
	struct perf_event_attr *attr = e->os_data;
	int ret;

	ret = pfm_mips_get_encoding(this, e);
	if (ret != PFM_SUCCESS)
		return ret;

	if (e->count != 2) {
		DPRINT("unexpected encoding count=%d\n", e->count);
		return PFM_ERR_INVAL;
	}
	attr->type = PERF_TYPE_RAW;

	/*
	 * priv levels are ignored because they are managed
	 * directly through perf excl_*.
	 */
	attr->config = e->codes[0] >> 5;

	/*
	 * codes[1] contains counter mask supported by the event.
	 * Events support either odd or even indexed counters
	 * except for cycles (code = 0) and instructions (code =1)
	 * which work on all counters.
	 *
	 * The kernel expects bit 7 of config to indicate whether
	 * the event works only on odd-indexed counters
	 */
	if ((e->codes[1] & 0x2) && attr->config > 1)
		attr->config |= 1ULL << 7;

	return PFM_SUCCESS;
}

void
pfm_mips_perf_validate_pattrs(void *this, pfmlib_event_desc_t *e)
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
			/*
			 * with perf_event, priv levels under full
			 * control of perf_event.
			 */
			if (  e->pattrs[i].idx == MIPS_ATTR_K
			    ||e->pattrs[i].idx == MIPS_ATTR_U
			    ||e->pattrs[i].idx == MIPS_ATTR_S
			    ||e->pattrs[i].idx == MIPS_ATTR_E)
				compact = 1;
		}
		/*
		 * remove perf_event generic attributes not supported
		 * by MIPS
		 */
		if (e->pattrs[i].ctrl == PFM_ATTR_CTRL_PERF_EVENT) {
			/* no precise sampling on MIPS */
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
