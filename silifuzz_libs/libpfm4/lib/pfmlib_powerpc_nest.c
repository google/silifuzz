/*
 * pfmlib_powerpc_nest.c
 */

#include "pfmlib_priv.h"
#include "pfmlib_power_priv.h"
#include "events/powerpc_nest_events.h"

static int pfm_powerpc_nest_detect(void* this)
{
    if (__is_processor(PV_POWER8))
        return PFM_SUCCESS;
    return PFM_ERR_NOTSUPP;
}

pfmlib_pmu_t powerpc_nest_mcs_read_support={
    .desc           = "POWERPC_NEST_MCS_RD_BW",
    .name           = "powerpc_nest_mcs_read",
    .pmu            = PFM_PMU_POWERPC_NEST_MCS_READ_BW,
    .perf_name      = "Nest_MCS_Read_BW",
    .pme_count      = LIBPFM_ARRAY_SIZE(powerpc_nest_read_pe),
    .type           = PFM_PMU_TYPE_UNCORE,
    .num_cntrs      = 4,
    .num_fixed_cntrs    = 0,
    .max_encoding       = 1,
    .pe         = powerpc_nest_read_pe,
    .pmu_detect     = pfm_powerpc_nest_detect,
    .get_event_encoding[PFM_OS_NONE] = pfm_gen_powerpc_get_encoding,
    PFMLIB_ENCODE_PERF(pfm_gen_powerpc_get_nest_perf_encoding),
    PFMLIB_VALID_PERF_PATTRS(pfm_gen_powerpc_perf_validate_pattrs),
    .get_event_first    = pfm_gen_powerpc_get_event_first,
    .get_event_next     = pfm_gen_powerpc_get_event_next,
    .event_is_valid     = pfm_gen_powerpc_event_is_valid,
    .validate_table     = pfm_gen_powerpc_validate_table,
    .get_event_info     = pfm_gen_powerpc_get_event_info,
    .get_event_attr_info    = pfm_gen_powerpc_get_event_attr_info,
};

pfmlib_pmu_t powerpc_nest_mcs_write_support={
    .desc           = "POWERPC_NEST_MCS_WR_BW",
    .name           = "powerpc_nest_mcs_write",
    .pmu            = PFM_PMU_POWERPC_NEST_MCS_WRITE_BW,
    .perf_name      = "Nest_MCS_Write_BW",
    .pme_count      = LIBPFM_ARRAY_SIZE(powerpc_nest_write_pe),
    .type           = PFM_PMU_TYPE_UNCORE,
    .num_cntrs      = 4,
    .num_fixed_cntrs    = 0,
    .max_encoding       = 1,
    .pe         = powerpc_nest_write_pe,
    .pmu_detect     = pfm_powerpc_nest_detect,
    .get_event_encoding[PFM_OS_NONE] = pfm_gen_powerpc_get_encoding,
    PFMLIB_ENCODE_PERF(pfm_gen_powerpc_get_nest_perf_encoding),
    PFMLIB_VALID_PERF_PATTRS(pfm_gen_powerpc_perf_validate_pattrs),
    .get_event_first    = pfm_gen_powerpc_get_event_first,
    .get_event_next     = pfm_gen_powerpc_get_event_next,
    .event_is_valid     = pfm_gen_powerpc_event_is_valid,
    .validate_table     = pfm_gen_powerpc_validate_table,
    .get_event_info     = pfm_gen_powerpc_get_event_info,
    .get_event_attr_info    = pfm_gen_powerpc_get_event_attr_info,
};
