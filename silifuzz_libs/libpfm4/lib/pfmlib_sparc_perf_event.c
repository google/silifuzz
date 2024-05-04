/*
 * pfmlib_sparc_perf_event.c : perf_event SPARC functions
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

/* private headers */
#include "pfmlib_priv.h"		/* library private */
#include "pfmlib_sparc_priv.h"		/* architecture private */
#include "pfmlib_perf_event_priv.h"

int
pfm_sparc_get_perf_encoding(void *this, pfmlib_event_desc_t *e)
{
	struct perf_event_attr *attr = e->os_data;
	int ret;

	ret = pfm_sparc_get_encoding(this, e);
	if (ret != PFM_SUCCESS)
		return ret;

	attr->type = PERF_TYPE_RAW;
	attr->config = (e->codes[0] << 16) | e->codes[1];

	return PFM_SUCCESS;
}

void
pfm_sparc_perf_validate_pattrs(void *this, pfmlib_event_desc_t *e)
{
	int i, compact;

	for (i = 0; i < e->npattrs; i++) {
		compact = 0;

		/* umasks never conflict */
		if (e->pattrs[i].type == PFM_ATTR_UMASK)
			continue;

		/*
		 * with perf_events, u and k are handled at the OS level
		 * via attr.exclude_* fields
		 */
		if (e->pattrs[i].ctrl == PFM_ATTR_CTRL_PMU) {

			if (e->pattrs[i].idx == SPARC_ATTR_U
					|| e->pattrs[i].idx == SPARC_ATTR_K
					|| e->pattrs[i].idx == SPARC_ATTR_H)
				compact = 1;
		}

		if (e->pattrs[i].ctrl == PFM_ATTR_CTRL_PERF_EVENT) {

			/* No precise mode on SPARC */
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
