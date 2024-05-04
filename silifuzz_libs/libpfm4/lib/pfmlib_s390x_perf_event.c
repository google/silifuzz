/*
 * perf_event for Linux on IBM System z
 *
 * Copyright IBM Corp. 2012
 * Contributed by Hendrik Brueckner <brueckner@linux.vnet.ibm.com>
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

/* private library and arch headers */
#include "pfmlib_priv.h"
#include "pfmlib_s390x_priv.h"
#include "pfmlib_perf_event_priv.h"


/*
 * The s390 Performance Measurement counter facility does not have a fixed
 * type number anymore. This was caused by linux kernel commits
 * 66d258c5b0488 perf/core: Optimize perf_init_event()
 * and its necessary follow on commit
 * 6a82e23f45fe0 s390/cpumf: Adjust registration of s390 PMU device drivers
 *
 * Now read out the current type number from a sysfs file named
 * /sys/devices/cpum_cf/type. If it does not exist there is no CPU-MF counter
 * facility installed or activated.
 *
 * As the CPU Measurement counter facility does not change on a running
 * system, read out the type value on first read and cache it.
 *
 * There are several PMUs for s390, so find the correct one first and return
 * its PMU type value assigned at system boot time.
 */
static struct pfm_s390_perf_aptt {	/* Perf attribute PMU type table */
	pfm_pmu_t pmutype;		/* PMU Type number */
	const char *fname;		/* File name to read type from */
	unsigned int value;		/* Type value, 0 --> unused */
} pfm_s390_perf_aptt[] = {
	{
		.pmutype = PFM_PMU_S390X_CPUM_CF,
		.fname = "/sys/bus/event_source/devices/cpum_cf/type"
	},
	{
		.pmutype = PFM_PMU_S390X_CPUM_SF,
		.fname = "/sys/bus/event_source/devices/cpum_sf/type"
	},
};
#define S390_APTT_COUNT LIBPFM_ARRAY_SIZE(pfm_s390_perf_aptt)

static int pfm_s390_get_perf_attr_type(pfm_pmu_t pmutype)
{
	int cpum_cf_type;
	size_t buflen;
	char *buffer;
	FILE *fp;
	size_t i;

	/* Find type of PMU and return known and cached value */
	for (i = 0; i < S390_APTT_COUNT; ++i) {
		if (pfm_s390_perf_aptt[i].pmutype == pmutype)
			break;
	}

	if (i == S390_APTT_COUNT)
		return PFM_ERR_NOTFOUND;

	if (pfm_s390_perf_aptt[i].value)
		return pfm_s390_perf_aptt[i].value;

	/* Value unknown, read from file */
	fp = fopen(pfm_s390_perf_aptt[i].fname, "r");
	if (fp == NULL)
		return PFM_ERR_NOTFOUND;

	buffer = NULL;

	if (pfmlib_getl(&buffer, &buflen, fp) != -1 &&
	    sscanf(buffer, "%u", &cpum_cf_type) == -1)
		cpum_cf_type = PERF_TYPE_RAW;

	fclose(fp);
	free(buffer);

	pfm_s390_perf_aptt[i].value = cpum_cf_type;
	return cpum_cf_type;
}

int pfm_s390x_get_perf_encoding(void *this, pfmlib_event_desc_t *e)
{
	pfmlib_pmu_t *pmu = this;
	struct perf_event_attr *attr = e->os_data;
	int rc;

	if (!pmu->get_event_encoding[PFM_OS_NONE])
		return PFM_ERR_NOTSUPP;

	/* set up raw pmu event encoding */
	rc = pmu->get_event_encoding[PFM_OS_NONE](this, e);
	if (rc == PFM_SUCCESS) {
		/* currently use raw events only */
		rc = pfm_s390_get_perf_attr_type(pmu->pmu);
		if (rc > 0) {		/* PMU types are positive */
			attr->type = rc;
			attr->config = e->codes[0];
			rc = PFM_SUCCESS;
		}
	}

	return rc;
}

void
pfm_s390x_perf_validate_pattrs(void *this, pfmlib_event_desc_t *e)
{
	int i, compact;

	for (i=0; i < e->npattrs; i++) {
		compact = 0;

		/* umasks never conflict */
		if (e->pattrs[i].type == PFM_ATTR_UMASK)
			continue;

		if (e->pattrs[i].ctrl == PFM_ATTR_CTRL_PERF_EVENT) {
			/* No precise mode on s390x */
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
