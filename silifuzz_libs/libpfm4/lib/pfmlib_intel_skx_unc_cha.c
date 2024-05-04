/*
 * pfmlib_intel_skx_unc_cha.c : Intel SKX CHA-Box uncore PMU
 *
 * Copyright (c) 2017 Google LLC
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
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* private headers */
#include "pfmlib_priv.h"
#include "pfmlib_intel_x86_priv.h"
#include "pfmlib_intel_snbep_unc_priv.h"
#include "events/intel_skx_unc_cha_events.h"

static void
display_cha(void *this, pfmlib_event_desc_t *e, void *val)
{
	const intel_x86_entry_t *pe = this_pe(this);
	pfm_snbep_unc_reg_t *reg = val;
	pfm_snbep_unc_reg_t f;

	__pfm_vbprintf("[UNC_CHA=0x%"PRIx64" event=0x%x umask=0x%x en=%d "
		       "inv=%d edge=%d thres=%d tid_en=%d] %s\n",
			reg->val,
			reg->cha.unc_event,
			reg->cha.unc_umask,
			reg->cha.unc_en,
			reg->cha.unc_inv,
			reg->cha.unc_edge,
			reg->cha.unc_thres,
			reg->cha.unc_tid,
			pe[e->event].name);

	if (e->count == 1)
		return;

	f.val = e->codes[1];

	__pfm_vbprintf("[UNC_CHA_FILTER0=0x%"PRIx64" thread_id=%d source=0x%x state=0x%x]\n",
			f.val,
			f.skx_cha_filt0.tid,
			f.skx_cha_filt0.sid,
			f.skx_cha_filt0.state);

	if (e->count == 2)
		return;

	f.val = e->codes[2];

	__pfm_vbprintf("[UNC_CHA_FILTER1=0x%"PRIx64" rem=%d loc=%d all_opc=%d nm=%d"
		      " not_nm=%d opc0=0x%x opc1=0x%x nc=%d isoc=%d]\n",
			f.val,
			f.skx_cha_filt1.rem,
			f.skx_cha_filt1.loc,
			f.skx_cha_filt1.all_opc,
			f.skx_cha_filt1.nm,
			f.skx_cha_filt1.not_nm,
			f.skx_cha_filt1.opc0,
			f.skx_cha_filt1.opc1,
			f.skx_cha_filt1.nc,
			f.skx_cha_filt1.isoc);
}

#define DEFINE_CHA(n) \
pfmlib_pmu_t intel_skx_unc_cha##n##_support = {\
	.desc			= "Intel SkylakeX CHA"#n" uncore",\
	.name			= "skx_unc_cha"#n,\
	.perf_name		= "uncore_cha_"#n,\
	.pmu			= PFM_PMU_INTEL_SKX_UNC_CHA##n,\
	.pme_count		= LIBPFM_ARRAY_SIZE(intel_skx_unc_c_pe),\
	.type			= PFM_PMU_TYPE_UNCORE,\
	.num_cntrs		= 4,\
	.num_fixed_cntrs	= 0,\
	.max_encoding		= 2,\
	.pe			= intel_skx_unc_c_pe,\
	.atdesc			= snbep_unc_mods,\
	.flags			= PFMLIB_PMU_FL_RAW_UMASK|INTEL_PMU_FL_UNC_CHA,\
	.pmu_detect		= pfm_intel_skx_unc_detect,\
	.get_event_encoding[PFM_OS_NONE] = pfm_intel_snbep_unc_get_encoding,\
	 PFMLIB_ENCODE_PERF(pfm_intel_snbep_unc_get_perf_encoding),\
	 PFMLIB_OS_DETECT(pfm_intel_x86_perf_detect), \
	.get_event_first	= pfm_intel_x86_get_event_first,\
	.get_event_next		= pfm_intel_x86_get_event_next,\
	.event_is_valid		= pfm_intel_x86_event_is_valid,\
	.validate_table		= pfm_intel_x86_validate_table,\
	.get_event_info		= pfm_intel_x86_get_event_info,\
	.get_event_attr_info	= pfm_intel_x86_get_event_attr_info,\
	PFMLIB_VALID_PERF_PATTRS(pfm_intel_snbep_unc_perf_validate_pattrs),\
	.get_event_nattrs	= pfm_intel_x86_get_event_nattrs,\
	.can_auto_encode	= pfm_intel_x86_can_auto_encode, \
	.display_reg		= display_cha,\
}

DEFINE_CHA(0);
DEFINE_CHA(1);
DEFINE_CHA(2);
DEFINE_CHA(3);
DEFINE_CHA(4);
DEFINE_CHA(5);
DEFINE_CHA(6);
DEFINE_CHA(7);
DEFINE_CHA(8);
DEFINE_CHA(9);
DEFINE_CHA(10);
DEFINE_CHA(11);
DEFINE_CHA(12);
DEFINE_CHA(13);
DEFINE_CHA(14);
DEFINE_CHA(15);
DEFINE_CHA(16);
DEFINE_CHA(17);
DEFINE_CHA(18);
DEFINE_CHA(19);
DEFINE_CHA(20);
DEFINE_CHA(21);
DEFINE_CHA(22);
DEFINE_CHA(23);
DEFINE_CHA(24);
DEFINE_CHA(25);
DEFINE_CHA(26);
DEFINE_CHA(27);
