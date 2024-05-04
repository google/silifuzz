/*
 * pfmlib_amd64_rapl.c : AMD RAPL PMU
 *
 * Copyright 2021 Google LLC
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
 * AMD RAPL PMU (AMD Zen2)
 */

/* private headers */
#include "pfmlib_priv.h"
/*
 * for now, we reuse the x86 table entry format and callback to avoid duplicating
 * code. We may revisit this later on
 */
#include "pfmlib_amd64_priv.h"

extern pfmlib_pmu_t amd64_rapl_support;

static const amd64_entry_t amd64_rapl_zen2[]={
  { .name   = "RAPL_ENERGY_PKG",
    .desc   = "Number of Joules consumed by all cores and Last level cache on the package. Unit is 2^-32 Joules",
    .code   = 0x2,
  }
};

static int
pfm_amd64_rapl_detect(void *this)
{
	int ret, rev;

	ret = pfm_amd64_detect(this);
	if (ret != PFM_SUCCESS)
		return ret;

	rev = pfm_amd64_cfg.revision;
	switch(rev) {
	case PFM_PMU_AMD64_FAM17H_ZEN2:
	case PFM_PMU_AMD64_FAM19H_ZEN3:
	case PFM_PMU_AMD64_FAM19H_ZEN4:
		ret = PFM_SUCCESS;
		break;
	default:
		ret = PFM_ERR_NOTSUPP;
	}
	return ret;
}

static int
pfm_amd64_rapl_get_encoding(void *this, pfmlib_event_desc_t *e)

{
	const amd64_entry_t *pe;

	pe = this_pe(this);

	e->fstr[0] = '\0';

	e->codes[0] = pe[e->event].code;
	e->count = 1;
	evt_strcat(e->fstr, "%s", pe[e->event].name);

	__pfm_vbprintf("[0x%"PRIx64" event=0x%x] %s\n",
		       e->codes[0],
		       e->codes[0], e->fstr);

	return PFM_SUCCESS;
}

/*
 * number modifiers for RAPL
 * define an empty modifier to avoid firing the
 * sanity pfm_amd64_validate_table(). We are
 * using this function to avoid duplicating code.
 */
static const pfmlib_attr_desc_t amd64_rapl_mods[]=
{ { 0, } };

pfmlib_pmu_t amd64_rapl_support={
	.desc			= "AMD64 RAPL",
	.name			= "amd64_rapl",
	.perf_name		= "power",
	.pmu			= PFM_PMU_AMD64_RAPL,
	.pme_count		= LIBPFM_ARRAY_SIZE(amd64_rapl_zen2),
	.type			= PFM_PMU_TYPE_UNCORE,
	.num_cntrs		= 0,
	.num_fixed_cntrs	= 3,
	.max_encoding		= 1,
	.pe			= amd64_rapl_zen2,
	.pmu_detect		= pfm_amd64_rapl_detect,
	.atdesc			= amd64_rapl_mods,

	.get_event_encoding[PFM_OS_NONE] = pfm_amd64_rapl_get_encoding,
	 PFMLIB_ENCODE_PERF(pfm_amd64_get_perf_encoding),
	.get_event_first	= pfm_amd64_get_event_first,
	.get_event_next		= pfm_amd64_get_event_next,
	.event_is_valid		= pfm_amd64_event_is_valid,
	.validate_table		= pfm_amd64_validate_table,
	.get_event_info		= pfm_amd64_get_event_info,
	.get_event_attr_info	= pfm_amd64_get_event_attr_info,
	 PFMLIB_VALID_PERF_PATTRS(pfm_amd64_perf_validate_pattrs),
	.get_event_nattrs	= pfm_amd64_get_event_nattrs,
};
