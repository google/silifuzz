/*
 * Copyright (C) IBM Corporation, 2009.  All rights reserved.
 * Contributed by Corey Ashford (cjashfor@us.ibm.com)
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
 * pfmlib_gen_powerpc.c
 *
 * Support for libpfm4 for the PowerPC 970, 970MP, Power4,4+,5,5+,6,7 processors.
 */

#include <stdlib.h>
#include <string.h>


/* private headers */
#include "pfmlib_priv.h"
#include "pfmlib_power_priv.h"

int
pfm_gen_powerpc_get_event_info(void *this, int pidx, pfm_event_info_t *info)
{
	pfmlib_pmu_t *pmu = this;
	const pme_power_entry_t *pe = this_pe(this);

	/*
	 * pmu and idx filled out by caller
	 */
	info->name = pe[pidx].pme_name;
	info->desc = pe[pidx].pme_long_desc;
	info->code = pe[pidx].pme_code;
	info->equiv = NULL;
	info->idx   = pidx; /* private index */
	info->pmu   = pmu->pmu;
	info->is_precise = 0;
	info->support_hw_smpl = 0;

	info->nattrs = 0;

	return PFM_SUCCESS;
}

int
pfm_gen_powerpc_get_event_attr_info(void *this, int pidx, int umask_idx, pfmlib_event_attr_info_t *info)
{
	/* No attributes are supported */
	return PFM_ERR_ATTR;
}

int
pfm_gen_powerpc_get_encoding(void *this, pfmlib_event_desc_t *e)
{
	const pme_power_entry_t *pe = this_pe(this);

	e->count = 1;
	e->codes[0] = (uint64_t)pe[e->event].pme_code;

	evt_strcat(e->fstr, "%s", pe[e->event].pme_name);

	return PFM_SUCCESS;
}

int
pfm_gen_powerpc_get_event_first(void *this)
{
	return 0;
}

int
pfm_gen_powerpc_get_event_next(void *this, int idx)
{
	pfmlib_pmu_t *p = this;

	if (idx >= (p->pme_count-1))
		return -1;

	return idx+1;
}

int
pfm_gen_powerpc_event_is_valid(void *this, int pidx)
{
	pfmlib_pmu_t *p = this;
	return pidx >= 0 && pidx < p->pme_count;
}

int
pfm_gen_powerpc_validate_table(void *this, FILE *fp)
{
	pfmlib_pmu_t *pmu = this;
	const pme_power_entry_t *pe = this_pe(this);
	int i;
	int ret = PFM_ERR_INVAL;

	for(i=0; i < pmu->pme_count; i++) {
		if (!pe[i].pme_name) {
			fprintf(fp, "pmu: %s event%d: :: no name\n", pmu->name, i);
			goto error;
		}
		if (!pe[i].pme_long_desc) {
			fprintf(fp, "pmu: %s event%d: %s :: no description\n", pmu->name, i, pe[i].pme_name);
			goto error;
		}
	}
	ret = PFM_SUCCESS;
error:
	return ret;
}
