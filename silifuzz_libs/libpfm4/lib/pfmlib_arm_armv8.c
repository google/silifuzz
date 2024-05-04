/*
 * pfmlib_arm_armv8.c : support for ARMv8 processors
 *
 * Copyright (c) 2014 Google Inc. All rights reserved
 * Contributed by Stephane Eranian <eranian@gmail.com>
 *
 * Copyright (c) 2022, NVIDIA CORPORATION & AFFILIATES.
 * Contributed by John Linford <jlinford@nvidia.com>
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
 */
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>

/* private headers */
#include "pfmlib_priv.h"			/* library private */
#include "pfmlib_arm_priv.h"

#include "events/arm_cortex_a57_events.h"    /* A57 event tables */
#include "events/arm_cortex_a53_events.h"    /* A53 event tables */
#include "events/arm_xgene_events.h"         /* Applied Micro X-Gene tables */
#include "events/arm_cavium_tx2_events.h"    	/* Marvell ThunderX2 tables */
#include "events/arm_marvell_tx2_unc_events.h" 	/* Marvell ThunderX2 PMU tables */
#include "events/arm_fujitsu_a64fx_events.h"	/* Fujitsu A64FX PMU tables */
#include "events/arm_neoverse_n1_events.h"	/* ARM Neoverse N1 table */
#include "events/arm_neoverse_v1_events.h"	/* Arm Neoverse V1 table */
#include "events/arm_hisilicon_kunpeng_events.h" /* HiSilicon Kunpeng PMU tables */
#include "events/arm_hisilicon_kunpeng_unc_events.h" /* Hisilicon Kunpeng PMU uncore tables */

static int
pfm_arm_detect_n1(void *this)
{
	int ret;

	ret = pfm_arm_detect(this);
	if (ret != PFM_SUCCESS)
		return PFM_ERR_NOTSUPP;

	if ((pfm_arm_cfg.implementer == 0x41) && /* ARM */
		(pfm_arm_cfg.part == 0xd0c)) { /* Neoverse N1 */
			return PFM_SUCCESS;
	}
	return PFM_ERR_NOTSUPP;
}

static int
pfm_arm_detect_v1(void *this)
{
	int ret;

	ret = pfm_arm_detect(this);
	if (ret != PFM_SUCCESS)
		return PFM_ERR_NOTSUPP;

	if ((pfm_arm_cfg.implementer == 0x41) && /* ARM */
		(pfm_arm_cfg.part == 0xd40)) { /* Neoverse V1 */
			return PFM_SUCCESS;
	}
	return PFM_ERR_NOTSUPP;
}

static int
pfm_arm_detect_cortex_a57(void *this)
{
	int ret;

	ret = pfm_arm_detect(this);
	if (ret != PFM_SUCCESS)
		return PFM_ERR_NOTSUPP;

	if ((pfm_arm_cfg.implementer == 0x41) && /* ARM */
		(pfm_arm_cfg.part == 0xd07)) { /* Cortex A57 */
			return PFM_SUCCESS;
	}
	return PFM_ERR_NOTSUPP;
}

static int
pfm_arm_detect_cortex_a53(void *this)
{
	int ret;

	ret = pfm_arm_detect(this);
	if (ret != PFM_SUCCESS)
		return PFM_ERR_NOTSUPP;

	if ((pfm_arm_cfg.implementer == 0x41) && /* ARM */
		(pfm_arm_cfg.part == 0xd03)) { /* Cortex A53 */
			return PFM_SUCCESS;
	}
	return PFM_ERR_NOTSUPP;
}

static int
pfm_arm_detect_xgene(void *this)
{
	int ret;

	ret = pfm_arm_detect(this);
	if (ret != PFM_SUCCESS)
		return PFM_ERR_NOTSUPP;

	if ((pfm_arm_cfg.implementer == 0x50) && /* Applied Micro */
		(pfm_arm_cfg.part == 0x000)) { /* Applied Micro X-Gene */
			return PFM_SUCCESS;
	}
	return PFM_ERR_NOTSUPP;
}

static int
pfm_arm_detect_thunderx2(void *this)
{
	int ret;

	ret = pfm_arm_detect(this);
	if (ret != PFM_SUCCESS)
		return PFM_ERR_NOTSUPP;

	if ((pfm_arm_cfg.implementer == 0x42) && /* Broadcom */
		(pfm_arm_cfg.part == 0x516)) { /* Thunder2x */
			return PFM_SUCCESS;
	}
	if ((pfm_arm_cfg.implementer == 0x43) && /* Cavium */
		(pfm_arm_cfg.part == 0xaf)) { /* Thunder2x */
			return PFM_SUCCESS;
	}
	return PFM_ERR_NOTSUPP;
}

static int
pfm_arm_detect_a64fx(void *this)
{
	int ret;

	ret = pfm_arm_detect(this);
	if (ret != PFM_SUCCESS)
		return PFM_ERR_NOTSUPP;

	if ((pfm_arm_cfg.implementer == 0x46) && /* Fujitsu */
		(pfm_arm_cfg.part == 0x001)) { /* a64fx */
			return PFM_SUCCESS;
	}
	return PFM_ERR_NOTSUPP;
}

static int
pfm_arm_detect_hisilicon_kunpeng(void *this)
{
	int ret;

	ret = pfm_arm_detect(this);
	if (ret != PFM_SUCCESS)
		return PFM_ERR_NOTSUPP;

	if ((pfm_arm_cfg.implementer == 0x48) && /* Hisilicon */
	    (pfm_arm_cfg.part == 0xd01)) { /* Kunpeng */
			return PFM_SUCCESS;
	}
	return PFM_ERR_NOTSUPP;
}

/* ARM Cortex A57 support */
pfmlib_pmu_t arm_cortex_a57_support={
	.desc			= "ARM Cortex A57",
	.name			= "arm_ac57",
	.pmu			= PFM_PMU_ARM_CORTEX_A57,
	.pme_count		= LIBPFM_ARRAY_SIZE(arm_cortex_a57_pe),
	.type			= PFM_PMU_TYPE_CORE,
	.supported_plm          = ARMV8_PLM,
	.pe			= arm_cortex_a57_pe,

	.pmu_detect		= pfm_arm_detect_cortex_a57,
	.max_encoding		= 1,
	.num_cntrs		= 6,

	.get_event_encoding[PFM_OS_NONE] = pfm_arm_get_encoding,
	 PFMLIB_ENCODE_PERF(pfm_arm_get_perf_encoding),
	.get_event_first	= pfm_arm_get_event_first,
	.get_event_next		= pfm_arm_get_event_next,
	.event_is_valid		= pfm_arm_event_is_valid,
	.validate_table		= pfm_arm_validate_table,
	.get_event_info		= pfm_arm_get_event_info,
	.get_event_attr_info	= pfm_arm_get_event_attr_info,
	 PFMLIB_VALID_PERF_PATTRS(pfm_arm_perf_validate_pattrs),
	.get_event_nattrs	= pfm_arm_get_event_nattrs,
};

/* ARM Cortex A53 support */
pfmlib_pmu_t arm_cortex_a53_support={
	.desc			= "ARM Cortex A53",
	.name			= "arm_ac53",
	.pmu			= PFM_PMU_ARM_CORTEX_A53,
	.pme_count		= LIBPFM_ARRAY_SIZE(arm_cortex_a53_pe),
	.type			= PFM_PMU_TYPE_CORE,
	.supported_plm          = ARMV8_PLM,
	.pe			= arm_cortex_a53_pe,

	.pmu_detect		= pfm_arm_detect_cortex_a53,
	.max_encoding		= 1,
	.num_cntrs		= 6,

	.get_event_encoding[PFM_OS_NONE] = pfm_arm_get_encoding,
	 PFMLIB_ENCODE_PERF(pfm_arm_get_perf_encoding),
	.get_event_first	= pfm_arm_get_event_first,
	.get_event_next		= pfm_arm_get_event_next,
	.event_is_valid		= pfm_arm_event_is_valid,
	.validate_table		= pfm_arm_validate_table,
	.get_event_info		= pfm_arm_get_event_info,
	.get_event_attr_info	= pfm_arm_get_event_attr_info,
	 PFMLIB_VALID_PERF_PATTRS(pfm_arm_perf_validate_pattrs),
	.get_event_nattrs	= pfm_arm_get_event_nattrs,
};

/* Applied Micro X-Gene support */
pfmlib_pmu_t arm_xgene_support={
	.desc			= "Applied Micro X-Gene",
	.name			= "arm_xgene",
	.pmu			= PFM_PMU_ARM_XGENE,
	.pme_count		= LIBPFM_ARRAY_SIZE(arm_xgene_pe),
	.type			= PFM_PMU_TYPE_CORE,
	.supported_plm          = ARMV8_PLM,
	.pe			= arm_xgene_pe,

	.pmu_detect		= pfm_arm_detect_xgene,
	.max_encoding		= 1,
	.num_cntrs		= 4,

	.get_event_encoding[PFM_OS_NONE] = pfm_arm_get_encoding,
	 PFMLIB_ENCODE_PERF(pfm_arm_get_perf_encoding),
	.get_event_first	= pfm_arm_get_event_first,
	.get_event_next		= pfm_arm_get_event_next,
	.event_is_valid		= pfm_arm_event_is_valid,
	.validate_table		= pfm_arm_validate_table,
	.get_event_info		= pfm_arm_get_event_info,
	.get_event_attr_info	= pfm_arm_get_event_attr_info,
	 PFMLIB_VALID_PERF_PATTRS(pfm_arm_perf_validate_pattrs),
	.get_event_nattrs	= pfm_arm_get_event_nattrs,
};

/* Marvell ThunderX2 support */
pfmlib_pmu_t arm_thunderx2_support={
	.desc			= "Cavium ThunderX2",
	.name			= "arm_thunderx2",
	.pmu			= PFM_PMU_ARM_THUNDERX2,
	.pme_count		= LIBPFM_ARRAY_SIZE(arm_thunderx2_pe),
	.type			= PFM_PMU_TYPE_CORE,
	.supported_plm          = ARMV8_PLM,
	.pe			= arm_thunderx2_pe,

	.pmu_detect		= pfm_arm_detect_thunderx2,
	.max_encoding		= 1,
	.num_cntrs		= 6,

	.get_event_encoding[PFM_OS_NONE] = pfm_arm_get_encoding,
	 PFMLIB_ENCODE_PERF(pfm_arm_get_perf_encoding),
	.get_event_first	= pfm_arm_get_event_first,
	.get_event_next		= pfm_arm_get_event_next,
	.event_is_valid		= pfm_arm_event_is_valid,
	.validate_table		= pfm_arm_validate_table,
	.get_event_info		= pfm_arm_get_event_info,
	.get_event_attr_info	= pfm_arm_get_event_attr_info,
	 PFMLIB_VALID_PERF_PATTRS(pfm_arm_perf_validate_pattrs),
	.get_event_nattrs	= pfm_arm_get_event_nattrs,
};

/* Fujitsu A64FX support */
pfmlib_pmu_t arm_fujitsu_a64fx_support={
	.desc			= "Fujitsu A64FX",
	.name			= "arm_a64fx",
	.pmu			= PFM_PMU_ARM_A64FX,
	.pme_count		= LIBPFM_ARRAY_SIZE(arm_a64fx_pe),
	.type			= PFM_PMU_TYPE_CORE,
	.supported_plm          = ARMV8_PLM,
	.pe			= arm_a64fx_pe,

	.pmu_detect		= pfm_arm_detect_a64fx,
	.max_encoding		= 1,
	.num_cntrs		= 8,

	.get_event_encoding[PFM_OS_NONE] = pfm_arm_get_encoding,
	 PFMLIB_ENCODE_PERF(pfm_arm_get_perf_encoding),
	.get_event_first	= pfm_arm_get_event_first,
	.get_event_next		= pfm_arm_get_event_next,
	.event_is_valid		= pfm_arm_event_is_valid,
	.validate_table		= pfm_arm_validate_table,
	.get_event_info		= pfm_arm_get_event_info,
	.get_event_attr_info	= pfm_arm_get_event_attr_info,
	 PFMLIB_VALID_PERF_PATTRS(pfm_arm_perf_validate_pattrs),
	.get_event_nattrs	= pfm_arm_get_event_nattrs,
};

/* HiSilicon Kunpeng support */
pfmlib_pmu_t arm_hisilicon_kunpeng_support={
	.desc           = "Hisilicon Kunpeng",
	.name           = "arm_kunpeng",
	.pmu            = PFM_PMU_ARM_KUNPENG,
	.pme_count      = LIBPFM_ARRAY_SIZE(arm_kunpeng_pe),
	.type           = PFM_PMU_TYPE_CORE,
	.supported_plm  = ARMV8_PLM,
	.pe             = arm_kunpeng_pe,
	.pmu_detect     = pfm_arm_detect_hisilicon_kunpeng,
	.max_encoding   = 1,
	.num_cntrs      = 12,
	.num_fixed_cntrs      = 1,

	.get_event_encoding[PFM_OS_NONE] = pfm_arm_get_encoding,
	PFMLIB_ENCODE_PERF(pfm_arm_get_perf_encoding),
	.get_event_first        = pfm_arm_get_event_first,
	.get_event_next         = pfm_arm_get_event_next,
	.event_is_valid         = pfm_arm_event_is_valid,
	.validate_table         = pfm_arm_validate_table,
	.get_event_info         = pfm_arm_get_event_info,
	.get_event_attr_info    = pfm_arm_get_event_attr_info,
	PFMLIB_VALID_PERF_PATTRS(pfm_arm_perf_validate_pattrs),
	.get_event_nattrs       = pfm_arm_get_event_nattrs,
};

/* Hisilicon Kunpeng support */
// For uncore, each socket has a separate perf name, otherwise they are the same, use macro

#define DEFINE_KUNPENG_DDRC(n,m) \
pfmlib_pmu_t arm_hisilicon_kunpeng_sccl##n##_ddrc##m##_support={ \
	.desc           = "Hisilicon Kunpeng SCCL"#n" DDRC"#m, \
	.name           = "hisi_sccl"#n"_ddrc"#m, \
	.perf_name      = "hisi_sccl"#n"_ddrc"#m, \
	.pmu            = PFM_PMU_ARM_KUNPENG_UNC_SCCL##n##_DDRC##m, \
	.pme_count      = LIBPFM_ARRAY_SIZE(arm_kunpeng_unc_ddrc_pe), \
	.type           = PFM_PMU_TYPE_UNCORE, \
	.pe             = arm_kunpeng_unc_ddrc_pe, \
	.pmu_detect     = pfm_arm_detect_hisilicon_kunpeng, \
	.max_encoding   = 1, \
	.num_cntrs      = 4, \
	.get_event_encoding[PFM_OS_NONE] = pfm_kunpeng_unc_get_event_encoding, \
	 PFMLIB_ENCODE_PERF(pfm_kunpeng_unc_get_perf_encoding), \
	.get_event_first	= pfm_arm_get_event_first, \
	.get_event_next		= pfm_arm_get_event_next, \
	.event_is_valid		= pfm_arm_event_is_valid, \
	.validate_table		= pfm_arm_validate_table, \
	.get_event_info		= pfm_arm_get_event_info, \
	.get_event_attr_info	= pfm_arm_get_event_attr_info, \
	 PFMLIB_VALID_PERF_PATTRS(pfm_arm_perf_validate_pattrs), \
	.get_event_nattrs	= pfm_arm_get_event_nattrs, \
};

DEFINE_KUNPENG_DDRC(1,0);
DEFINE_KUNPENG_DDRC(1,1);
DEFINE_KUNPENG_DDRC(1,2);
DEFINE_KUNPENG_DDRC(1,3);
DEFINE_KUNPENG_DDRC(3,0);
DEFINE_KUNPENG_DDRC(3,1);
DEFINE_KUNPENG_DDRC(3,2);
DEFINE_KUNPENG_DDRC(3,3);
DEFINE_KUNPENG_DDRC(5,0);
DEFINE_KUNPENG_DDRC(5,1);
DEFINE_KUNPENG_DDRC(5,2);
DEFINE_KUNPENG_DDRC(5,3);
DEFINE_KUNPENG_DDRC(7,0);
DEFINE_KUNPENG_DDRC(7,1);
DEFINE_KUNPENG_DDRC(7,2);
DEFINE_KUNPENG_DDRC(7,3);

#define DEFINE_KUNPENG_HHA(n,m) \
pfmlib_pmu_t arm_hisilicon_kunpeng_sccl##n##_hha##m##_support={ \
	.desc           = "Hisilicon Kunpeng SCCL"#n" HHA"#m, \
	.name           = "hisi_sccl"#n"_hha"#m, \
	.perf_name      = "hisi_sccl"#n"_hha"#m, \
	.pmu            = PFM_PMU_ARM_KUNPENG_UNC_SCCL##n##_HHA##m, \
	.pme_count      = LIBPFM_ARRAY_SIZE(arm_kunpeng_unc_hha_pe), \
	.type           = PFM_PMU_TYPE_UNCORE, \
	.pe             = arm_kunpeng_unc_hha_pe, \
	.pmu_detect     = pfm_arm_detect_hisilicon_kunpeng, \
	.max_encoding   = 1, \
	.num_cntrs      = 4, \
	.get_event_encoding[PFM_OS_NONE] = pfm_kunpeng_unc_get_event_encoding, \
	 PFMLIB_ENCODE_PERF(pfm_kunpeng_unc_get_perf_encoding), \
	.get_event_first	= pfm_arm_get_event_first, \
	.get_event_next		= pfm_arm_get_event_next, \
	.event_is_valid		= pfm_arm_event_is_valid, \
	.validate_table		= pfm_arm_validate_table, \
	.get_event_info		= pfm_arm_get_event_info, \
	.get_event_attr_info	= pfm_arm_get_event_attr_info, \
	 PFMLIB_VALID_PERF_PATTRS(pfm_arm_perf_validate_pattrs), \
	.get_event_nattrs	= pfm_arm_get_event_nattrs, \
};

DEFINE_KUNPENG_HHA(1,2);
DEFINE_KUNPENG_HHA(1,3);
DEFINE_KUNPENG_HHA(3,0);
DEFINE_KUNPENG_HHA(3,1);
DEFINE_KUNPENG_HHA(5,6);
DEFINE_KUNPENG_HHA(5,7);
DEFINE_KUNPENG_HHA(7,4);
DEFINE_KUNPENG_HHA(7,5);

#define DEFINE_KUNPENG_L3C(n,m) \
pfmlib_pmu_t arm_hisilicon_kunpeng_sccl##n##_l3c##m##_support={ \
	.desc           = "Hisilicon Kunpeng SCCL"#n" L3C"#m, \
	.name           = "hisi_sccl"#n"_l3c"#m, \
	.perf_name      = "hisi_sccl"#n"_l3c"#m, \
	.pmu            = PFM_PMU_ARM_KUNPENG_UNC_SCCL##n##_L3C##m, \
	.pme_count      = LIBPFM_ARRAY_SIZE(arm_kunpeng_unc_l3c_pe), \
	.type           = PFM_PMU_TYPE_UNCORE, \
	.pe             = arm_kunpeng_unc_l3c_pe, \
	.pmu_detect     = pfm_arm_detect_hisilicon_kunpeng, \
	.max_encoding   = 1, \
	.num_cntrs      = 4, \
	.get_event_encoding[PFM_OS_NONE] = pfm_kunpeng_unc_get_event_encoding, \
	 PFMLIB_ENCODE_PERF(pfm_kunpeng_unc_get_perf_encoding), \
	.get_event_first	= pfm_arm_get_event_first, \
	.get_event_next		= pfm_arm_get_event_next, \
	.event_is_valid		= pfm_arm_event_is_valid, \
	.validate_table		= pfm_arm_validate_table, \
	.get_event_info		= pfm_arm_get_event_info, \
	.get_event_attr_info	= pfm_arm_get_event_attr_info, \
	 PFMLIB_VALID_PERF_PATTRS(pfm_arm_perf_validate_pattrs), \
	.get_event_nattrs	= pfm_arm_get_event_nattrs, \
};

DEFINE_KUNPENG_L3C(1,10);
DEFINE_KUNPENG_L3C(1,11);
DEFINE_KUNPENG_L3C(1,12);
DEFINE_KUNPENG_L3C(1,13);
DEFINE_KUNPENG_L3C(1,14);
DEFINE_KUNPENG_L3C(1,15);
DEFINE_KUNPENG_L3C(1,8);
DEFINE_KUNPENG_L3C(1,9);
DEFINE_KUNPENG_L3C(3,0);
DEFINE_KUNPENG_L3C(3,1);
DEFINE_KUNPENG_L3C(3,2);
DEFINE_KUNPENG_L3C(3,3);
DEFINE_KUNPENG_L3C(3,4);
DEFINE_KUNPENG_L3C(3,5);
DEFINE_KUNPENG_L3C(3,6);
DEFINE_KUNPENG_L3C(3,7);
DEFINE_KUNPENG_L3C(5,24);
DEFINE_KUNPENG_L3C(5,25);
DEFINE_KUNPENG_L3C(5,26);
DEFINE_KUNPENG_L3C(5,27);
DEFINE_KUNPENG_L3C(5,28);
DEFINE_KUNPENG_L3C(5,29);
DEFINE_KUNPENG_L3C(5,30);
DEFINE_KUNPENG_L3C(5,31);
DEFINE_KUNPENG_L3C(7,16);
DEFINE_KUNPENG_L3C(7,17);
DEFINE_KUNPENG_L3C(7,18);
DEFINE_KUNPENG_L3C(7,19);
DEFINE_KUNPENG_L3C(7,20);
DEFINE_KUNPENG_L3C(7,21);
DEFINE_KUNPENG_L3C(7,22);
DEFINE_KUNPENG_L3C(7,23);

// For uncore, each socket has a separate perf name, otherwise they are the same, use macro

#define DEFINE_TX2_DMC(n) \
pfmlib_pmu_t arm_thunderx2_dmc##n##_support={ \
	.desc			= "Marvell ThunderX2 Node"#n" DMC", \
	.name			= "tx2_dmc"#n, \
	.perf_name		= "uncore_dmc_"#n, \
	.pmu			= PFM_PMU_ARM_THUNDERX2_DMC##n, \
	.pme_count		= LIBPFM_ARRAY_SIZE(arm_thunderx2_unc_dmc_pe), \
	.type			= PFM_PMU_TYPE_UNCORE, \
	.pe			= arm_thunderx2_unc_dmc_pe, \
	.pmu_detect		= pfm_arm_detect_thunderx2, \
	.max_encoding		= 1, \
	.num_cntrs		= 4, \
	.get_event_encoding[PFM_OS_NONE] = pfm_tx2_unc_get_event_encoding, \
	 PFMLIB_ENCODE_PERF(pfm_tx2_unc_get_perf_encoding),		\
	.get_event_first	= pfm_arm_get_event_first, \
	.get_event_next		= pfm_arm_get_event_next,  \
	.event_is_valid		= pfm_arm_event_is_valid,  \
	.validate_table		= pfm_arm_validate_table,  \
	.get_event_info		= pfm_arm_get_event_info,  \
	.get_event_attr_info	= pfm_arm_get_event_attr_info,	\
	 PFMLIB_VALID_PERF_PATTRS(pfm_arm_perf_validate_pattrs),\
	.get_event_nattrs	= pfm_arm_get_event_nattrs, \
};

DEFINE_TX2_DMC(0);
DEFINE_TX2_DMC(1);

#define DEFINE_TX2_LLC(n) \
pfmlib_pmu_t arm_thunderx2_llc##n##_support={ \
	.desc			= "Marvell ThunderX2 node "#n" LLC", \
	.name			= "tx2_llc"#n, \
	.perf_name		= "uncore_l3c_"#n, \
	.pmu			= PFM_PMU_ARM_THUNDERX2_LLC##n, \
	.pme_count		= LIBPFM_ARRAY_SIZE(arm_thunderx2_unc_llc_pe), \
	.type			= PFM_PMU_TYPE_UNCORE, \
	.pe			= arm_thunderx2_unc_llc_pe, \
	.pmu_detect		= pfm_arm_detect_thunderx2, \
	.max_encoding		= 1, \
	.num_cntrs		= 4, \
	.get_event_encoding[PFM_OS_NONE] = pfm_tx2_unc_get_event_encoding, \
	 PFMLIB_ENCODE_PERF(pfm_tx2_unc_get_perf_encoding),		\
	.get_event_first	= pfm_arm_get_event_first, \
	.get_event_next		= pfm_arm_get_event_next,  \
	.event_is_valid		= pfm_arm_event_is_valid,  \
	.validate_table		= pfm_arm_validate_table,  \
	.get_event_info		= pfm_arm_get_event_info,  \
	.get_event_attr_info	= pfm_arm_get_event_attr_info,	\
	 PFMLIB_VALID_PERF_PATTRS(pfm_arm_perf_validate_pattrs),\
	.get_event_nattrs	= pfm_arm_get_event_nattrs, \
};

DEFINE_TX2_LLC(0);
DEFINE_TX2_LLC(1);

#define DEFINE_TX2_CCPI(n) \
pfmlib_pmu_t arm_thunderx2_ccpi##n##_support={ \
	.desc			= "Marvell ThunderX2 node "#n" Cross-Socket Interconnect", \
	.name			= "tx2_ccpi"#n, \
	.perf_name		= "uncore_ccpi2_"#n, \
	.pmu			= PFM_PMU_ARM_THUNDERX2_CCPI##n, \
	.pme_count		= LIBPFM_ARRAY_SIZE(arm_thunderx2_unc_ccpi_pe), \
	.type			= PFM_PMU_TYPE_UNCORE, \
	.pe			= arm_thunderx2_unc_ccpi_pe, \
	.pmu_detect		= pfm_arm_detect_thunderx2, \
	.max_encoding		= 1, \
	.num_cntrs		= 4, \
	.get_event_encoding[PFM_OS_NONE] = pfm_tx2_unc_get_event_encoding, \
	 PFMLIB_ENCODE_PERF(pfm_tx2_unc_get_perf_encoding),		\
	.get_event_first	= pfm_arm_get_event_first, \
	.get_event_next		= pfm_arm_get_event_next,  \
	.event_is_valid		= pfm_arm_event_is_valid,  \
	.validate_table		= pfm_arm_validate_table,  \
	.get_event_info		= pfm_arm_get_event_info,  \
	.get_event_attr_info	= pfm_arm_get_event_attr_info,	\
	 PFMLIB_VALID_PERF_PATTRS(pfm_arm_perf_validate_pattrs),\
	.get_event_nattrs	= pfm_arm_get_event_nattrs, \
};

DEFINE_TX2_CCPI(0);
DEFINE_TX2_CCPI(1);

pfmlib_pmu_t arm_n1_support={
	.desc			= "ARM Neoverse N1",
	.name			= "arm_n1",
	.pmu			= PFM_PMU_ARM_N1,
	.pme_count		= LIBPFM_ARRAY_SIZE(arm_n1_pe),
	.type			= PFM_PMU_TYPE_CORE,
	.supported_plm          = ARMV8_PLM,
	.pe			= arm_n1_pe,

	.pmu_detect		= pfm_arm_detect_n1,
	.max_encoding		= 1,
	.num_cntrs		= 6,

	.get_event_encoding[PFM_OS_NONE] = pfm_arm_get_encoding,
	 PFMLIB_ENCODE_PERF(pfm_arm_get_perf_encoding),
	.get_event_first	= pfm_arm_get_event_first,
	.get_event_next		= pfm_arm_get_event_next,
	.event_is_valid		= pfm_arm_event_is_valid,
	.validate_table		= pfm_arm_validate_table,
	.get_event_info		= pfm_arm_get_event_info,
	.get_event_attr_info	= pfm_arm_get_event_attr_info,
	 PFMLIB_VALID_PERF_PATTRS(pfm_arm_perf_validate_pattrs),
	.get_event_nattrs	= pfm_arm_get_event_nattrs,
};

pfmlib_pmu_t arm_v1_support={
	.desc			= "Arm Neoverse V1",
	.name			= "arm_v1",
	.pmu			= PFM_PMU_ARM_V1,
	.pme_count		= LIBPFM_ARRAY_SIZE(arm_v1_pe),
	.type			= PFM_PMU_TYPE_CORE,
	.supported_plm  = ARMV8_PLM,
	.pe             = arm_v1_pe,

	.pmu_detect		= pfm_arm_detect_v1,
	.max_encoding		= 1,
	.num_cntrs		= 6,

	.get_event_encoding[PFM_OS_NONE] = pfm_arm_get_encoding,
	 PFMLIB_ENCODE_PERF(pfm_arm_get_perf_encoding),
	.get_event_first	= pfm_arm_get_event_first,
	.get_event_next		= pfm_arm_get_event_next,
	.event_is_valid		= pfm_arm_event_is_valid,
	.validate_table		= pfm_arm_validate_table,
	.get_event_info		= pfm_arm_get_event_info,
	.get_event_attr_info	= pfm_arm_get_event_attr_info,
	 PFMLIB_VALID_PERF_PATTRS(pfm_arm_perf_validate_pattrs),
	.get_event_nattrs	= pfm_arm_get_event_nattrs,
};
