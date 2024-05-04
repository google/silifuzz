/*
 * pfmlib_intel_spr_unc_cha.c : Intel SPR CHA-Box uncore PMU
 *
 * Copyright (c) 2024 Google LLC
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
#include "events/intel_spr_unc_cha_events.h"

static void
display_cha(void *this, pfmlib_event_desc_t *e, void *val)
{
	const intel_x86_entry_t *pe = this_pe(this);
	pfm_snbep_unc_reg_t *reg = val;
	pfm_snbep_unc_reg_t f;

	__pfm_vbprintf("[UNC_CHA=0x%"PRIx64" event=0x%x umask=0x%x en=%d "
		       "inv=%d edge=%d thres=%d tid_en=%d umask_ext=0x%x] %s\n",
			reg->val,
			reg->icx_cha.unc_event,
			reg->icx_cha.unc_umask,
			reg->icx_cha.unc_en,
			reg->icx_cha.unc_inv,
			reg->icx_cha.unc_edge,
			reg->icx_cha.unc_thres,
			reg->icx_cha.unc_tid,
			reg->icx_cha.unc_umask_ext,
			pe[e->event].name);

	if (e->count == 1)
		return;

	f.val = e->codes[1];

	__pfm_vbprintf("[UNC_CHA_FILTER0=0x%"PRIx64" thread_id=%d source=0x%x state=0x%x]\n",
			f.val,
			f.skx_cha_filt0.tid,
			f.skx_cha_filt0.sid,
			f.skx_cha_filt0.state);
}

#define DEFINE_CHA(n) \
pfmlib_pmu_t intel_spr_unc_cha##n##_support = {\
	.desc			= "Intel SapphireRapids CHA"#n" uncore",\
	.name			= "spr_unc_cha"#n,\
	.perf_name		= "uncore_cha_"#n,\
	.pmu			= PFM_PMU_INTEL_SPR_UNC_CHA##n,\
	.pme_count		= LIBPFM_ARRAY_SIZE(intel_spr_unc_cha_pe),\
	.type			= PFM_PMU_TYPE_UNCORE,\
	.num_cntrs		= 4,\
	.num_fixed_cntrs	= 0,\
	.max_encoding		= 2,\
	.pe			= intel_spr_unc_cha_pe,\
	.atdesc			= snbep_unc_mods,\
	.flags			= PFMLIB_PMU_FL_RAW_UMASK,\
	.pmu_detect		= pfm_intel_spr_unc_detect,\
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
DEFINE_CHA(28);
DEFINE_CHA(29);
DEFINE_CHA(30);
DEFINE_CHA(31);
DEFINE_CHA(32);
DEFINE_CHA(33);
DEFINE_CHA(34);
DEFINE_CHA(35);
DEFINE_CHA(36);
DEFINE_CHA(37);
DEFINE_CHA(38);
DEFINE_CHA(39);
DEFINE_CHA(40);
DEFINE_CHA(41);
DEFINE_CHA(42);
DEFINE_CHA(43);
DEFINE_CHA(44);
DEFINE_CHA(45);
DEFINE_CHA(46);
DEFINE_CHA(47);
DEFINE_CHA(48);
DEFINE_CHA(49);
DEFINE_CHA(50);
DEFINE_CHA(51);
DEFINE_CHA(52);
DEFINE_CHA(53);
DEFINE_CHA(54);
DEFINE_CHA(55);
DEFINE_CHA(56);
DEFINE_CHA(57);
DEFINE_CHA(58);
DEFINE_CHA(59);
