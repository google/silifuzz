#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <limits.h>

/* private headers */
#include "pfmlib_priv.h"
#include "pfmlib_perf_event_priv.h"
#include "pfmlib_arm_priv.h"

typedef union {
	uint64_t val;
	struct {
		unsigned long unc_res1:32;	/* reserved */
	} com; /* reserved space for future extensions */
} tx2_unc_data_t;

static void
display_com(void *this, pfmlib_event_desc_t *e, void *val)
{
	const arm_entry_t *pe = this_pe(this);
	tx2_unc_data_t *reg = val;

	__pfm_vbprintf("[UNC=0x%"PRIx64"] %s\n",
			reg->val,
			pe[e->event].name);
}

static void
display_reg(void *this, pfmlib_event_desc_t *e, tx2_unc_data_t reg)
{
	pfmlib_pmu_t *pmu = this;
	if (pmu->display_reg)
		pmu->display_reg(this, e, &reg);
	else
		display_com(this, e, &reg);
}


static int
find_pmu_type_by_name(const char *name)
{
	char filename[PATH_MAX];
	FILE *fp;
	int ret, type;

	if (!name)
		return PFM_ERR_NOTSUPP;

	sprintf(filename, "/sys/bus/event_source/devices/%s/type", name);

	fp = fopen(filename, "r");
	if (!fp)
		return PFM_ERR_NOTSUPP;

	ret = fscanf(fp, "%d", &type);
	if (ret != 1)
		type = PFM_ERR_NOTSUPP;

	fclose(fp);

	return type;
}

int
pfm_tx2_unc_get_event_encoding(void *this, pfmlib_event_desc_t *e)
{
	//from pe field in for the uncore, get the array with all the event defs
	const arm_entry_t *event_list = this_pe(this);
	tx2_unc_data_t reg;
	//get code for the event from the table
	reg.val = event_list[e->event].code;
	//pass the data back to the caller
	e->codes[0] = reg.val;
	e->count = 1;
	evt_strcat(e->fstr, "%s", event_list[e->event].name);
	display_reg(this, e, reg);
	return PFM_SUCCESS;
}

int
pfm_tx2_unc_get_perf_encoding(void *this, pfmlib_event_desc_t *e)
{
	pfmlib_pmu_t *pmu = this;
	struct perf_event_attr *attr = e->os_data;
	tx2_unc_data_t reg;
	int ret;

	if (!pmu->get_event_encoding[PFM_OS_NONE])
		return PFM_ERR_NOTSUPP;

	ret = pmu->get_event_encoding[PFM_OS_NONE](this, e);
	if (ret != PFM_SUCCESS)
		return ret;
	//get pmu type to probe
	ret = find_pmu_type_by_name(pmu->perf_name);
	if (ret < 0)
		return ret;

	attr->type = ret;
	//get code to provide to the uncore pmu probe
	reg.val = e->codes[0];
	attr->config = reg.val;

	// if needed, can use attr->config1 or attr->config2 for extra info from event structure defines e->codes[i]

	// uncore measures at all priv levels
	attr->exclude_hv = 0;
	attr->exclude_kernel = 0;
	attr->exclude_user = 0;

	return PFM_SUCCESS;
}
