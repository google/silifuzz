/*
 * pfmlib_torrent.c : IBM Torrent support
 *
 * Copyright (C) IBM Corporation, 2010.  All rights reserved.
 * Contributed by Corey Ashford (cjashfor@us.ibm.com)
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
#include <dirent.h>
#include <string.h>

#include "pfmlib_priv.h"
#include "pfmlib_power_priv.h"
#include "events/torrent_events.h"

const pfmlib_attr_desc_t torrent_modifiers[] = {
	PFM_ATTR_I("type", "Counter type: 0 = 2x64-bit counters w/32-bit prescale, 1 = 4x32-bit counters w/16-bit prescale, 2 = 2x32-bit counters w/no prescale, 3 = 4x16-bit counters w/no prescale"),
	PFM_ATTR_I("sel", "Sample period / Cmd Increment select: 0 = 256 cycles/ +16, 1 = 512 cycles / +8, 2 = 1024 cycles / +4, 3 = 2048 cycles / +2"),
	PFM_ATTR_I("lo_cmp", "Low threshold compare: 0..31"),
	PFM_ATTR_I("hi_cmp", "High threshold compare: 0..31"),
	PFM_ATTR_NULL
};

static inline int pfm_torrent_attr2mod(void *this, int pidx, int attr_idx)
{
	const pme_torrent_entry_t *pe = this_pe(this);
	size_t x;
	int n;

	n = attr_idx;

	pfmlib_for_each_bit(x, pe[pidx].pme_modmsk) {
		if (n == 0)
			break;
		n--;
	}
	return x;
}

/**
 * torrent_pmu_detect
 *
 * Determine if this machine has a Torrent chip
 *
 **/
static int pfm_torrent_detect(void* this)
{
	struct dirent *de;
	DIR *dir;
	int ret  = PFM_ERR_NOTSUPP;

	/* If /proc/device-tree/hfi-iohub@<torrent_chip_id> exists,
	 * this machine has an accessible Torrent chip */
	dir = opendir("/proc/device-tree");
	if (!dir)
		return PFM_ERR_NOTSUPP;

	while ((de = readdir(dir)) != NULL) {
		if (!strncmp(de->d_name, "hfi-iohub@", 10)) {
			ret = PFM_SUCCESS;
			break;
		}
	}
	closedir(dir);
	return ret;
}

static int
pfm_torrent_get_event_info(void *this, int pidx, pfm_event_info_t *info)
{
	pfmlib_pmu_t *pmu = this;
	const pme_torrent_entry_t *pe = this_pe(this);

	info->name = pe[pidx].pme_name;
	info->desc = pe[pidx].pme_desc ? pe[pidx].pme_desc : "";
	info->code = pe[pidx].pme_code;
	info->equiv = NULL;
	info->idx   = pidx; /* private index */
	info->pmu   = pmu->pmu;
	info->dtype = PFM_DTYPE_UINT64;
	info->is_precise = 0;

	/* unit masks + modifiers */
	info->nattrs = pfmlib_popcnt((unsigned long)pe[pidx].pme_modmsk);

	return PFM_SUCCESS;
}

static int
pfm_torrent_get_event_attr_info(void *this, int idx, int attr_idx,
				  pfmlib_event_attr_info_t *info)
{
	int m;

	m = pfm_torrent_attr2mod(this, idx, attr_idx);

	info->name = modx(torrent_modifiers, m, name);
	info->desc = modx(torrent_modifiers, m, desc);
	info->code = m;
	info->type = modx(torrent_modifiers, m, type);
	info->equiv = NULL;
	info->is_dfl = 0;
	info->is_precise = 0;
	info->idx = m;
	info->dfl_val64 = 0;
	info->ctrl = PFM_ATTR_CTRL_PMU;

	return PFM_SUCCESS;
}

static int
pfm_torrent_validate_table(void *this, FILE *fp)
{
	pfmlib_pmu_t *pmu = this;
	const pme_torrent_entry_t *pe = this_pe(this);
	int i, ret = PFM_ERR_INVAL;

	for (i = 0; i < pmu->pme_count; i++) {
		if (!pe[i].pme_name) {
			fprintf(fp, "pmu: %s event%d: :: no name\n", pmu->name, i);
			goto error;
		}
		if (pe[i].pme_code == 0) {
			fprintf(fp, "pmu: %s event%d: %s :: event code is 0\n", pmu->name, i, pe[i].pme_name);
			goto error;
		}
	}
	ret = PFM_SUCCESS;
error:
	return ret;
}

static int
pfm_torrent_get_encoding(void *this, pfmlib_event_desc_t *e)
{
	const pme_torrent_entry_t *pe = this_pe(this);
	uint32_t torrent_pmu;
	int i, mod;

	e->fstr[0] = '\0'; /* initialize the fully-qualified event string */

	e->count = 1;
	e->codes[0] = (uint64_t)pe[e->event].pme_code;

	for (i = 0; i < e->nattrs; i++) {

		mod = pfm_torrent_attr2mod(this, e->event, e->attrs[i].id);
		torrent_pmu = pe[e->event].pme_code & (TORRENT_SPACE | TORRENT_PMU_MASK);

		switch (torrent_pmu) {
		case TORRENT_PBUS_MCD:
			switch (mod) {
			case TORRENT_ATTR_MCD_TYPE:
				if (e->attrs[i].ival <= 3) {
					e->codes[0] |= e->attrs[i].ival << TORRENT_ATTR_MCD_TYPE_SHIFT;
				} else {
					DPRINT("value of attribute \'type\' - %" PRIu64 " - is not in the range 0..3.\n", e->attrs[i].ival);
					return PFM_ERR_ATTR_VAL;
				}
				break;
			default:
				DPRINT("unknown attribute for TORRENT_POWERBUS_MCD - %d\n", mod);
				return PFM_ERR_ATTR;
		}
		break;
		case TORRENT_PBUS_UTIL:
			switch (mod) {
			case TORRENT_ATTR_UTIL_SEL:
				if (e->attrs[i].ival <= 3) {
					e->codes[0] |= e->attrs[i].ival << TORRENT_ATTR_UTIL_SEL_SHIFT;
				} else {
					DPRINT("value of attribute \'sel\' - %" PRIu64 " - is not in the range 0..3.\n", e->attrs[i].ival);
					return PFM_ERR_ATTR_VAL;
				}
				break;
			case TORRENT_ATTR_UTIL_LO_CMP:
			case TORRENT_ATTR_UTIL_HI_CMP:
				if (e->attrs[i].ival <= 31) {
					e->codes[0] |= e->attrs[i].ival << TORRENT_ATTR_UTIL_CMP_SHIFT;
				} else {
					if (mod == TORRENT_ATTR_UTIL_LO_CMP)
						DPRINT("value of attribute \'lo_cmp\' - %" PRIu64 " - is not in the range 0..31.\n", e->attrs[i].ival);
					else
						DPRINT("value of attribute \'hi_cmp\' - %" PRIu64 " - is not in the range 0..31.\n", e->attrs[i].ival);
					return PFM_ERR_ATTR_VAL;
				}
		}
		break;
		default:
			DPRINT("attributes are unsupported for this Torrent PMU - code = %" PRIx32 "\n", torrent_pmu);
			return PFM_ERR_ATTR;
		}
	}
	return PFM_SUCCESS;
}

pfmlib_pmu_t torrent_support = {
	.pmu			= PFM_PMU_TORRENT,
	.name			= "power_torrent",
	.desc			= "IBM Power Torrent PMU",
	.pme_count		= PME_TORRENT_EVENT_COUNT,
	.pe			= torrent_pe,
	.max_encoding		= 1,
	.get_event_first	= pfm_gen_powerpc_get_event_first,
	.get_event_next		= pfm_gen_powerpc_get_event_next,
	.event_is_valid		= pfm_gen_powerpc_event_is_valid,
	.pmu_detect		= pfm_torrent_detect,
	.get_event_encoding[PFM_OS_NONE] = pfm_torrent_get_encoding,
	 PFMLIB_ENCODE_PERF(pfm_gen_powerpc_get_perf_encoding),
	 PFMLIB_VALID_PERF_PATTRS(pfm_gen_powerpc_perf_validate_pattrs),
	.validate_table		= pfm_torrent_validate_table,
	.get_event_info		= pfm_torrent_get_event_info,
	.get_event_attr_info	= pfm_torrent_get_event_attr_info,
};
