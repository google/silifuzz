/*
 * PMU support for the CPU-measurement facilities
 *
 * Copyright IBM Corp. 2012, 2014
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
#include <ctype.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/* private library and arch headers */
#include "pfmlib_priv.h"
#include "pfmlib_s390x_priv.h"
#include "pfmlib_perf_event_priv.h"
#include "events/s390x_cpumf_events.h"


#define CPUM_CF_DEVICE_DIR  "/sys/bus/event_source/devices/cpum_cf"
#define CPUM_SF_DEVICE_DIR  "/sys/bus/event_source/devices/cpum_sf"
#define SYS_INFO	    "/proc/sysinfo"
#define SERVICE_LEVEL	    "/proc/service_levels"
#define CF_VERSION_STR	    "CPU-MF: Counter facility: version="


/* CPU-measurement counter list (pmu events) */
static pme_cpumf_ctr_t *cpumcf_pe = NULL;

/* Detect the CPU-measurement counter and sampling facilities */
static int pfm_cpumcf_detect(void *this)
{
	if (access(CPUM_CF_DEVICE_DIR, R_OK))
		return PFM_ERR_NOTSUPP;
	return PFM_SUCCESS;
}

static int pfm_cpumsf_detect(void *this)
{
	if (access(CPUM_SF_DEVICE_DIR, R_OK))
		return PFM_ERR_NOTSUPP;
	return PFM_SUCCESS;
}

/* Parses the machine type that identifies an IBM mainframe.
 * These kind of information are from /proc/sysinfo.
 */
static long get_machine_type(void)
{
	long machine_type;
	size_t buflen, len;
	char *buffer, *tmp;
	FILE *fp;

	machine_type = 0;
	fp = fopen(SYS_INFO, "r");
	if (fp == NULL)
		goto out;

	buffer = NULL;
	while (pfmlib_getl(&buffer, &buflen, fp) != -1) {
		/* skip empty lines */
		if (*buffer == '\n')
			continue;

		/* look for 'Type:' entry */
		if (!strncmp("Type:", buffer, 5)) {
			tmp = buffer + 5;    /* set ptr after ':' */
			/* skip leading blanks */
			while (isspace(*tmp))
				tmp++;
			/* skip trailing blanks */
			len = strlen(tmp);
			while (len > 0 && isspace(tmp[len]))
				len--;
			tmp[len+1] = '\0';
			machine_type = strtol(tmp, NULL, 10);
			break;
		}
	}
	fclose(fp);
	free(buffer);
out:
	return machine_type;
}

static void get_cf_version(unsigned int *cfvn, unsigned int *csvn)
{
	int rc;
	FILE *fp;
	char *buffer;
	size_t buflen;

	*cfvn = *csvn = 0;
	fp = fopen(SERVICE_LEVEL, "r");
	if (fp == NULL)
		return;

	buffer = NULL;
	while (pfmlib_getl(&buffer, &buflen, fp) != -1) {
		/* skip empty lines */
		if (*buffer == '\n')
			continue;

		/* look for 'CPU-MF: Counter facility: version=' entry */
		if (!strncmp(CF_VERSION_STR, buffer, strlen(CF_VERSION_STR))) {
			rc = sscanf(buffer + strlen(CF_VERSION_STR), "%u.%u",
				    cfvn, csvn);
			if (rc != 2)
				*cfvn = *csvn = 0;
			break;
		}
	}
	fclose(fp);
	free(buffer);
}

/* Initialize the PMU representation for CPUMF.
 *
 * Set up the PMU events array based on
 *  - generic (basic, problem-state, and crypto-activaty) counter sets
 *  - the extended counter depending on the machine type
 */
static int pfm_cpumcf_init(void *this)
{
	pfmlib_pmu_t *pmu = this;
	unsigned int cfvn, csvn;
	const pme_cpumf_ctr_t *cfvn_set, *csvn_set, *ext_set;
	size_t cfvn_set_count, csvn_set_count, ext_set_count, pme_count;

	/* obtain counter first/second version number */
	get_cf_version(&cfvn, &csvn);

	/* counters based on first version number */
	switch (cfvn)
	{
	case 1:
		cfvn_set = cpumcf_fvn1_counters;
		cfvn_set_count = LIBPFM_ARRAY_SIZE(cpumcf_fvn1_counters);
		break;
	case 3:
		cfvn_set = cpumcf_fvn3_counters;
		cfvn_set_count = LIBPFM_ARRAY_SIZE(cpumcf_fvn3_counters);
		break;
	default:
		cfvn_set = NULL;
		cfvn_set_count = 0;
		break;
	}

	/* counters based on second version number */
	csvn_set = cpumcf_svn_generic_counters;
	csvn_set_count = LIBPFM_ARRAY_SIZE(cpumcf_svn_generic_counters);
	if (csvn < 6)	/* Crypto counter set enlarged for SVN == 6 */
		csvn_set_count -= CPUMF_SVN6_ECC;

	/* check and assign a machine-specific extended counter set */
	switch (get_machine_type()) {
	case 2097:  /* IBM System z10 EC */
	case 2098:  /* IBM System z10 BC */
		ext_set = cpumcf_z10_counters,
		ext_set_count = LIBPFM_ARRAY_SIZE(cpumcf_z10_counters);
		break;
	case 2817:  /* IBM zEnterprise 196 */
	case 2818:  /* IBM zEnterprise 114 */
		ext_set = cpumcf_z196_counters;
		ext_set_count = LIBPFM_ARRAY_SIZE(cpumcf_z196_counters);
		break;
	case 2827:  /* IBM zEnterprise EC12 */
	case 2828:  /* IBM zEnterprise BC12 */
		ext_set = cpumcf_zec12_counters;
		ext_set_count = LIBPFM_ARRAY_SIZE(cpumcf_zec12_counters);
		break;
	case 2964:  /* IBM z13  */
	case 2965:  /* IBM z13s */
		ext_set = cpumcf_z13_counters;
		ext_set_count = LIBPFM_ARRAY_SIZE(cpumcf_z13_counters);
		break;
	case 3906:  /* IBM z14  */
	case 3907:  /* IBM z14 ZR1  */
		ext_set = cpumcf_z14_counters;
		ext_set_count = LIBPFM_ARRAY_SIZE(cpumcf_z14_counters);
		break;
	case 8561:  /* IBM Machine types 8561 and 8562 */
	case 8562:
		ext_set = cpumcf_z15_counters;
		ext_set_count = LIBPFM_ARRAY_SIZE(cpumcf_z15_counters);
		break;
	case 3931:  /* IBM Machine types 3931 and 3932 */
	case 3932:
		ext_set = cpumcf_z16_counters;
		ext_set_count = LIBPFM_ARRAY_SIZE(cpumcf_z16_counters);
		break;
	default:
		/* No extended counter set for this machine type or there
		 * was an error retrieving the machine type */
		ext_set = NULL;
		ext_set_count = 0;
		break;
	}

	cpumcf_pe = calloc(sizeof(*cpumcf_pe),
			   cfvn_set_count + csvn_set_count + ext_set_count);
	if (cpumcf_pe == NULL)
		return PFM_ERR_NOMEM;

	pme_count = 0;
	memcpy(cpumcf_pe, cfvn_set, sizeof(*cpumcf_pe) * cfvn_set_count);
	pme_count += cfvn_set_count;
	memcpy((void *) (cpumcf_pe + pme_count), csvn_set,
	       sizeof(*cpumcf_pe) * csvn_set_count);
	pme_count += csvn_set_count;
	if (ext_set_count)
		memcpy((void *) (cpumcf_pe + pme_count),
		       ext_set, sizeof(*cpumcf_pe) * ext_set_count);
	pme_count += ext_set_count;

	pmu->pe = cpumcf_pe;
	pmu->pme_count = pme_count;

	/* CPUM-CF provides fixed counters only. The number of installed
	 * counters depends on the version and hardware model up to
	 * CPUMF_COUNTER_MAX.
	 */
	pmu->num_fixed_cntrs = pme_count;

	return PFM_SUCCESS;
}

static void pfm_cpumcf_exit(void *this)
{
	pfmlib_pmu_t *pmu = this;

	pmu->pme_count = 0;
	pmu->pe = NULL;

	free(cpumcf_pe);
}

static int pfm_cpumf_get_encoding(void *this, pfmlib_event_desc_t *e)
{
	const pme_cpumf_ctr_t *pe = this_pe(this);

	e->count = 1;	  /* number of encoded entries in e->codes */
	e->codes[0] = pe[e->event].ctrnum;
	evt_strcat(e->fstr, "%s", pe[e->event].name);

	return PFM_SUCCESS;
}

static int pfm_cpumf_get_event_first(void *this)
{
	pfmlib_pmu_t *pmu = this;

	return !!pmu->pme_count ? 0 : -1;
}

static int pfm_cpumf_get_event_next(void *this, int idx)
{
	pfmlib_pmu_t *pmu = this;

	if (idx >= (pmu->pme_count - 1))
		return -1;
	return idx + 1;
}

static int pfm_cpumf_event_is_valid(void *this, int idx)
{
	pfmlib_pmu_t *pmu = this;

	return (idx >= 0 && idx < pmu->pme_count);
}

static int pfm_cpumf_validate_table(void *this, FILE *fp)
{
	pfmlib_pmu_t *pmu = this;
	const pme_cpumf_ctr_t *pe = this_pe(this);
	int i, rc;

	rc = PFM_ERR_INVAL;
	for (i = 0; i < pmu->pme_count; i++) {
		if (!pe[i].name) {
			fprintf(fp, "pmu: %s event: %i: No name\n",
				pmu->name, i);
			goto failed;
		}
		if (!pe[i].desc) {
			fprintf(fp, "pmu: %s event: %i: No description\n",
				pmu->name, i);
			goto failed;
		}
	}

	rc = PFM_SUCCESS;
failed:
	return rc;
}

static int pfm_cpumcf_validate_table(void *this, FILE *fp)
{
	pfmlib_pmu_t *pmu = this;

	if (pmu->pme_count > CPUMF_COUNTER_MAX) {
		fprintf(fp, "pmu: %s: pme number exceeded maximum\n",
			pmu->name);
		return PFM_ERR_INVAL;
	}

	return pfm_cpumf_validate_table(this, fp);
}

static int pfm_cpumf_get_event_info(void *this, int idx,
				    pfm_event_info_t *info)
{
	pfmlib_pmu_t *pmu = this;
	const pme_cpumf_ctr_t *pe = this_pe(this);

	if (idx >= pmu->pme_count)
		return PFM_ERR_INVAL;

	info->name = pe[idx].name;
	info->desc = pe[idx].desc;
	info->code = pe[idx].ctrnum;
	info->equiv = NULL;
	info->idx = idx;
	info->pmu = pmu->pmu;
	info->is_precise = 0;

	info->nattrs = 0;	/* attributes are not supported */

	return PFM_SUCCESS;
}

static int pfm_cpumf_get_event_attr_info(void *this, int idx, int umask_idx,
					 pfmlib_event_attr_info_t *info)
{
	/* Attributes are not supported */
	return PFM_ERR_ATTR;
}

pfmlib_pmu_t s390x_cpum_cf_support = {
	.desc	   = "CPU-measurement counter facility",
	.name	   = "cpum_cf",
	.pmu	   = PFM_PMU_S390X_CPUM_CF,
	.type	   = PFM_PMU_TYPE_CORE,
	.flags	   = PFMLIB_PMU_FL_ARCH_DFL,
	.supported_plm = PFM_PLM3,

	.num_cntrs	 = 0,	  /* no general-purpose counters */
	.num_fixed_cntrs = CPUMF_COUNTER_MAX,	/* fixed counters only */
	.max_encoding	 = 1,

	.pe		 = NULL,
	.pme_count	 = 0,

	.pmu_detect    = pfm_cpumcf_detect,
	.pmu_init      = pfm_cpumcf_init,
	.pmu_terminate = pfm_cpumcf_exit,

	.get_event_encoding[PFM_OS_NONE] = pfm_cpumf_get_encoding,
		PFMLIB_ENCODE_PERF(pfm_s390x_get_perf_encoding),
	.get_event_first	= pfm_cpumf_get_event_first,
	.get_event_next		= pfm_cpumf_get_event_next,
	.event_is_valid		= pfm_cpumf_event_is_valid,
	.validate_table		= pfm_cpumcf_validate_table,
	.get_event_info		= pfm_cpumf_get_event_info,
	.get_event_attr_info	= pfm_cpumf_get_event_attr_info,
	 PFMLIB_VALID_PERF_PATTRS(pfm_s390x_perf_validate_pattrs),
};

pfmlib_pmu_t s390x_cpum_sf_support = {
	.desc	   = "CPU-measurement sampling facility",
	.name	   = "cpum_sf",
	.pmu	   = PFM_PMU_S390X_CPUM_SF,
	.type	   = PFM_PMU_TYPE_CORE,
	.flags	   = PFMLIB_PMU_FL_ARCH_DFL,

	.num_cntrs	 = 0,	/* no general-purpose counters */
	.num_fixed_cntrs = 2,	/* fixed counters only */
	.max_encoding	 = 1,

	.pe	   = cpumsf_counters,
	.pme_count = LIBPFM_ARRAY_SIZE(cpumsf_counters),

	.pmu_detect = pfm_cpumsf_detect,

	.get_event_encoding[PFM_OS_NONE] = pfm_cpumf_get_encoding,
		PFMLIB_ENCODE_PERF(pfm_s390x_get_perf_encoding),
	.get_event_first	= pfm_cpumf_get_event_first,
	.get_event_next		= pfm_cpumf_get_event_next,
	.event_is_valid		= pfm_cpumf_event_is_valid,
	.validate_table		= pfm_cpumf_validate_table,
	.get_event_info		= pfm_cpumf_get_event_info,
	.get_event_attr_info	= pfm_cpumf_get_event_attr_info,
	 PFMLIB_VALID_PERF_PATTRS(pfm_s390x_perf_validate_pattrs),
};
