/*
 * pfmlib_common.c: set of functions common to all PMU models
 *
 * Copyright (c) 2009 Google, Inc
 * Contributed by Stephane Eranian <eranian@gmail.com>
 *
 * Based on:
 * Copyright (c) 2001-2006 Hewlett-Packard Development Company, L.P.
 * Contributed by Stephane Eranian <eranian@hpl.hp.com>
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
 */
#include <sys/types.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <limits.h>

#include <perfmon/pfmlib.h>

#include "pfmlib_priv.h"

static pfmlib_pmu_t *pfmlib_pmus[]=
{

#ifdef CONFIG_PFMLIB_ARCH_IA64
#if 0
	&montecito_support,
	&itanium2_support,
	&itanium_support,
	&generic_ia64_support,	/* must always be last for IA-64 */
#endif
#endif

#ifdef CONFIG_PFMLIB_ARCH_I386
	/* 32-bit only processors */
	&intel_pii_support,
	&intel_ppro_support,
	&intel_p6_support,
	&intel_pm_support,
	&intel_coreduo_support,
#endif

#ifdef CONFIG_PFMLIB_ARCH_X86
	/* 32 and 64 bit processors */
	&netburst_support,
	&netburst_p_support,
	&amd64_k7_support,
	&amd64_k8_revb_support,
	&amd64_k8_revc_support,
	&amd64_k8_revd_support,
	&amd64_k8_reve_support,
	&amd64_k8_revf_support,
	&amd64_k8_revg_support,
	&amd64_fam10h_barcelona_support,
	&amd64_fam10h_shanghai_support,
	&amd64_fam10h_istanbul_support,
	&amd64_fam11h_turion_support,
	&amd64_fam12h_llano_support,
	&amd64_fam14h_bobcat_support,
	&amd64_fam15h_interlagos_support,
	&amd64_fam15h_nb_support,
	&amd64_fam16h_support,
	&amd64_fam17h_deprecated_support,
	&amd64_fam17h_zen1_support,
	&amd64_fam17h_zen2_support,
	&amd64_fam19h_zen3_support,
	&amd64_fam19h_zen4_support,
	&amd64_fam19h_zen3_l3_support,
	&amd64_rapl_support,
	&intel_core_support,
	&intel_atom_support,
	&intel_nhm_support,
	&intel_nhm_ex_support,
	&intel_nhm_unc_support,
	&intel_wsm_sp_support,
	&intel_wsm_dp_support,
	&intel_wsm_unc_support,
	&intel_snb_support,
	&intel_snb_unc_cbo0_support,
	&intel_snb_unc_cbo1_support,
	&intel_snb_unc_cbo2_support,
	&intel_snb_unc_cbo3_support,
	&intel_snb_ep_support,
	&intel_ivb_support,
	&intel_ivb_unc_cbo0_support,
	&intel_ivb_unc_cbo1_support,
	&intel_ivb_unc_cbo2_support,
	&intel_ivb_unc_cbo3_support,
	&intel_ivb_ep_support,
	&intel_hsw_support,
	&intel_hsw_ep_support,
	&intel_bdw_support,
	&intel_bdw_ep_support,
	&intel_skl_support,
	&intel_skx_support,
	&intel_clx_support,
	&intel_icl_support,
	&intel_icx_support,
	&intel_icx_unc_cha0_support,
	&intel_icx_unc_cha1_support,
	&intel_icx_unc_cha2_support,
	&intel_icx_unc_cha3_support,
	&intel_icx_unc_cha4_support,
	&intel_icx_unc_cha5_support,
	&intel_icx_unc_cha6_support,
	&intel_icx_unc_cha7_support,
	&intel_icx_unc_cha8_support,
	&intel_icx_unc_cha9_support,
	&intel_icx_unc_cha10_support,
	&intel_icx_unc_cha11_support,
	&intel_icx_unc_cha12_support,
	&intel_icx_unc_cha13_support,
	&intel_icx_unc_cha14_support,
	&intel_icx_unc_cha15_support,
	&intel_icx_unc_cha16_support,
	&intel_icx_unc_cha17_support,
	&intel_icx_unc_cha18_support,
	&intel_icx_unc_cha19_support,
	&intel_icx_unc_cha20_support,
	&intel_icx_unc_cha21_support,
	&intel_icx_unc_cha22_support,
	&intel_icx_unc_cha23_support,
	&intel_icx_unc_cha24_support,
	&intel_icx_unc_cha25_support,
	&intel_icx_unc_cha26_support,
	&intel_icx_unc_cha27_support,
	&intel_icx_unc_cha28_support,
	&intel_icx_unc_cha29_support,
	&intel_icx_unc_cha30_support,
	&intel_icx_unc_cha31_support,
	&intel_icx_unc_cha32_support,
	&intel_icx_unc_cha33_support,
	&intel_icx_unc_cha34_support,
	&intel_icx_unc_cha35_support,
	&intel_icx_unc_cha36_support,
	&intel_icx_unc_cha37_support,
	&intel_icx_unc_cha38_support,
	&intel_icx_unc_cha39_support,
	&intel_icx_unc_imc0_support,
	&intel_icx_unc_imc1_support,
	&intel_icx_unc_imc2_support,
	&intel_icx_unc_imc3_support,
	&intel_icx_unc_imc4_support,
	&intel_icx_unc_imc5_support,
	&intel_icx_unc_imc6_support,
	&intel_icx_unc_imc7_support,
	&intel_icx_unc_imc8_support,
	&intel_icx_unc_imc9_support,
	&intel_icx_unc_imc10_support,
	&intel_icx_unc_imc11_support,
	&intel_icx_unc_m2m0_support,
	&intel_icx_unc_m2m1_support,
	&intel_icx_unc_iio0_support,
	&intel_icx_unc_iio1_support,
	&intel_icx_unc_iio2_support,
	&intel_icx_unc_iio3_support,
	&intel_icx_unc_iio4_support,
	&intel_icx_unc_iio5_support,
	&intel_icx_unc_irp0_support,
	&intel_icx_unc_irp1_support,
	&intel_icx_unc_irp2_support,
	&intel_icx_unc_irp3_support,
	&intel_icx_unc_irp4_support,
	&intel_icx_unc_irp5_support,
	&intel_icx_unc_pcu_support,
	&intel_icx_unc_upi0_support,
	&intel_icx_unc_upi1_support,
	&intel_icx_unc_upi2_support,
	&intel_icx_unc_upi3_support,
	&intel_icx_unc_m3upi0_support,
	&intel_icx_unc_m3upi1_support,
	&intel_icx_unc_m3upi2_support,
	&intel_icx_unc_m3upi3_support,
	&intel_icx_unc_ubox_support,
	&intel_icx_unc_m2pcie0_support,
	&intel_icx_unc_m2pcie1_support,
	&intel_icx_unc_m2pcie2_support,
	&intel_spr_support,
	&intel_spr_unc_imc0_support,
	&intel_spr_unc_imc1_support,
	&intel_spr_unc_imc2_support,
	&intel_spr_unc_imc3_support,
	&intel_spr_unc_imc4_support,
	&intel_spr_unc_imc5_support,
	&intel_spr_unc_imc6_support,
	&intel_spr_unc_imc7_support,
	&intel_spr_unc_imc8_support,
	&intel_spr_unc_imc9_support,
	&intel_spr_unc_imc10_support,
	&intel_spr_unc_imc11_support,
	&intel_spr_unc_upi0_support,
	&intel_spr_unc_upi1_support,
	&intel_spr_unc_upi2_support,
	&intel_spr_unc_upi3_support,
	&intel_spr_unc_cha0_support,
	&intel_spr_unc_cha1_support,
	&intel_spr_unc_cha2_support,
	&intel_spr_unc_cha3_support,
	&intel_spr_unc_cha4_support,
	&intel_spr_unc_cha5_support,
	&intel_spr_unc_cha6_support,
	&intel_spr_unc_cha7_support,
	&intel_spr_unc_cha8_support,
	&intel_spr_unc_cha9_support,
	&intel_spr_unc_cha10_support,
	&intel_spr_unc_cha11_support,
	&intel_spr_unc_cha12_support,
	&intel_spr_unc_cha13_support,
	&intel_spr_unc_cha14_support,
	&intel_spr_unc_cha15_support,
	&intel_spr_unc_cha16_support,
	&intel_spr_unc_cha17_support,
	&intel_spr_unc_cha18_support,
	&intel_spr_unc_cha19_support,
	&intel_spr_unc_cha20_support,
	&intel_spr_unc_cha21_support,
	&intel_spr_unc_cha22_support,
	&intel_spr_unc_cha23_support,
	&intel_spr_unc_cha24_support,
	&intel_spr_unc_cha25_support,
	&intel_spr_unc_cha26_support,
	&intel_spr_unc_cha27_support,
	&intel_spr_unc_cha28_support,
	&intel_spr_unc_cha29_support,
	&intel_spr_unc_cha30_support,
	&intel_spr_unc_cha31_support,
	&intel_spr_unc_cha32_support,
	&intel_spr_unc_cha33_support,
	&intel_spr_unc_cha34_support,
	&intel_spr_unc_cha35_support,
	&intel_spr_unc_cha36_support,
	&intel_spr_unc_cha37_support,
	&intel_spr_unc_cha38_support,
	&intel_spr_unc_cha39_support,
	&intel_spr_unc_cha40_support,
	&intel_spr_unc_cha41_support,
	&intel_spr_unc_cha42_support,
	&intel_spr_unc_cha43_support,
	&intel_spr_unc_cha44_support,
	&intel_spr_unc_cha45_support,
	&intel_spr_unc_cha46_support,
	&intel_spr_unc_cha47_support,
	&intel_spr_unc_cha48_support,
	&intel_spr_unc_cha49_support,
	&intel_spr_unc_cha50_support,
	&intel_spr_unc_cha51_support,
	&intel_spr_unc_cha52_support,
	&intel_spr_unc_cha53_support,
	&intel_spr_unc_cha54_support,
	&intel_spr_unc_cha55_support,
	&intel_spr_unc_cha56_support,
	&intel_spr_unc_cha57_support,
	&intel_spr_unc_cha58_support,
	&intel_spr_unc_cha59_support,
	&intel_emr_support,
	&intel_adl_glc_support,
	&intel_adl_grt_support,
	&intel_rapl_support,
	&intel_snbep_unc_cb0_support,
	&intel_snbep_unc_cb1_support,
	&intel_snbep_unc_cb2_support,
	&intel_snbep_unc_cb3_support,
	&intel_snbep_unc_cb4_support,
	&intel_snbep_unc_cb5_support,
	&intel_snbep_unc_cb6_support,
	&intel_snbep_unc_cb7_support,
	&intel_snbep_unc_ha_support,
	&intel_snbep_unc_imc0_support,
	&intel_snbep_unc_imc1_support,
	&intel_snbep_unc_imc2_support,
	&intel_snbep_unc_imc3_support,
	&intel_snbep_unc_pcu_support,
	&intel_snbep_unc_qpi0_support,
	&intel_snbep_unc_qpi1_support,
	&intel_snbep_unc_ubo_support,
	&intel_snbep_unc_r2pcie_support,
	&intel_snbep_unc_r3qpi0_support,
	&intel_snbep_unc_r3qpi1_support,
	&intel_knc_support,
	&intel_slm_support,
	&intel_glm_support,
	&intel_tmt_support,
	&intel_ivbep_unc_cb0_support,
	&intel_ivbep_unc_cb1_support,
	&intel_ivbep_unc_cb2_support,
	&intel_ivbep_unc_cb3_support,
	&intel_ivbep_unc_cb4_support,
	&intel_ivbep_unc_cb5_support,
	&intel_ivbep_unc_cb6_support,
	&intel_ivbep_unc_cb7_support,
	&intel_ivbep_unc_cb8_support,
	&intel_ivbep_unc_cb9_support,
	&intel_ivbep_unc_cb10_support,
	&intel_ivbep_unc_cb11_support,
	&intel_ivbep_unc_cb12_support,
	&intel_ivbep_unc_cb13_support,
	&intel_ivbep_unc_cb14_support,
	&intel_ivbep_unc_ha0_support,
	&intel_ivbep_unc_ha1_support,
	&intel_ivbep_unc_imc0_support,
	&intel_ivbep_unc_imc1_support,
	&intel_ivbep_unc_imc2_support,
	&intel_ivbep_unc_imc3_support,
	&intel_ivbep_unc_imc4_support,
	&intel_ivbep_unc_imc5_support,
	&intel_ivbep_unc_imc6_support,
	&intel_ivbep_unc_imc7_support,
	&intel_ivbep_unc_pcu_support,
	&intel_ivbep_unc_qpi0_support,
	&intel_ivbep_unc_qpi1_support,
	&intel_ivbep_unc_qpi2_support,
	&intel_ivbep_unc_ubo_support,
	&intel_ivbep_unc_r2pcie_support,
	&intel_ivbep_unc_r3qpi0_support,
	&intel_ivbep_unc_r3qpi1_support,
	&intel_ivbep_unc_r3qpi2_support,
	&intel_ivbep_unc_irp_support,
	&intel_hswep_unc_cb0_support,
	&intel_hswep_unc_cb1_support,
	&intel_hswep_unc_cb2_support,
	&intel_hswep_unc_cb3_support,
	&intel_hswep_unc_cb4_support,
	&intel_hswep_unc_cb5_support,
	&intel_hswep_unc_cb6_support,
	&intel_hswep_unc_cb7_support,
	&intel_hswep_unc_cb8_support,
	&intel_hswep_unc_cb9_support,
	&intel_hswep_unc_cb10_support,
	&intel_hswep_unc_cb11_support,
	&intel_hswep_unc_cb12_support,
	&intel_hswep_unc_cb13_support,
	&intel_hswep_unc_cb14_support,
	&intel_hswep_unc_cb15_support,
	&intel_hswep_unc_cb16_support,
	&intel_hswep_unc_cb17_support,
	&intel_hswep_unc_ha0_support,
	&intel_hswep_unc_ha1_support,
	&intel_hswep_unc_imc0_support,
	&intel_hswep_unc_imc1_support,
	&intel_hswep_unc_imc2_support,
	&intel_hswep_unc_imc3_support,
	&intel_hswep_unc_imc4_support,
	&intel_hswep_unc_imc5_support,
	&intel_hswep_unc_imc6_support,
	&intel_hswep_unc_imc7_support,
	&intel_hswep_unc_pcu_support,
	&intel_hswep_unc_qpi0_support,
	&intel_hswep_unc_qpi1_support,
	&intel_hswep_unc_sb0_support,
	&intel_hswep_unc_sb1_support,
	&intel_hswep_unc_sb2_support,
	&intel_hswep_unc_sb3_support,
	&intel_hswep_unc_ubo_support,
	&intel_hswep_unc_r2pcie_support,
	&intel_hswep_unc_r3qpi0_support,
	&intel_hswep_unc_r3qpi1_support,
	&intel_hswep_unc_r3qpi2_support,
	&intel_hswep_unc_irp_support,
	&intel_knl_support,
	&intel_knl_unc_imc0_support,
	&intel_knl_unc_imc1_support,
	&intel_knl_unc_imc2_support,
	&intel_knl_unc_imc3_support,
	&intel_knl_unc_imc4_support,
	&intel_knl_unc_imc5_support,
	&intel_knl_unc_imc_uclk0_support,
	&intel_knl_unc_imc_uclk1_support,
	&intel_knl_unc_edc_uclk0_support,
	&intel_knl_unc_edc_uclk1_support,
	&intel_knl_unc_edc_uclk2_support,
	&intel_knl_unc_edc_uclk3_support,
	&intel_knl_unc_edc_uclk4_support,
	&intel_knl_unc_edc_uclk5_support,
	&intel_knl_unc_edc_uclk6_support,
	&intel_knl_unc_edc_uclk7_support,
	&intel_knl_unc_edc_eclk0_support,
	&intel_knl_unc_edc_eclk1_support,
	&intel_knl_unc_edc_eclk2_support,
	&intel_knl_unc_edc_eclk3_support,
	&intel_knl_unc_edc_eclk4_support,
	&intel_knl_unc_edc_eclk5_support,
	&intel_knl_unc_edc_eclk6_support,
	&intel_knl_unc_edc_eclk7_support,
	&intel_knl_unc_cha0_support,
	&intel_knl_unc_cha1_support,
	&intel_knl_unc_cha2_support,
	&intel_knl_unc_cha3_support,
	&intel_knl_unc_cha4_support,
	&intel_knl_unc_cha5_support,
	&intel_knl_unc_cha6_support,
	&intel_knl_unc_cha7_support,
	&intel_knl_unc_cha8_support,
	&intel_knl_unc_cha9_support,
	&intel_knl_unc_cha10_support,
	&intel_knl_unc_cha11_support,
	&intel_knl_unc_cha12_support,
	&intel_knl_unc_cha13_support,
	&intel_knl_unc_cha14_support,
	&intel_knl_unc_cha15_support,
	&intel_knl_unc_cha16_support,
	&intel_knl_unc_cha17_support,
	&intel_knl_unc_cha18_support,
	&intel_knl_unc_cha19_support,
	&intel_knl_unc_cha20_support,
	&intel_knl_unc_cha21_support,
	&intel_knl_unc_cha22_support,
	&intel_knl_unc_cha23_support,
	&intel_knl_unc_cha24_support,
	&intel_knl_unc_cha25_support,
	&intel_knl_unc_cha26_support,
	&intel_knl_unc_cha27_support,
	&intel_knl_unc_cha28_support,
	&intel_knl_unc_cha29_support,
	&intel_knl_unc_cha30_support,
	&intel_knl_unc_cha31_support,
	&intel_knl_unc_cha32_support,
	&intel_knl_unc_cha33_support,
	&intel_knl_unc_cha34_support,
	&intel_knl_unc_cha35_support,
	&intel_knl_unc_cha36_support,
	&intel_knl_unc_cha37_support,
	&intel_knl_unc_m2pcie_support,
	&intel_bdx_unc_cb0_support,
	&intel_bdx_unc_cb1_support,
	&intel_bdx_unc_cb2_support,
	&intel_bdx_unc_cb3_support,
	&intel_bdx_unc_cb4_support,
	&intel_bdx_unc_cb5_support,
	&intel_bdx_unc_cb6_support,
	&intel_bdx_unc_cb7_support,
	&intel_bdx_unc_cb8_support,
	&intel_bdx_unc_cb9_support,
	&intel_bdx_unc_cb10_support,
	&intel_bdx_unc_cb11_support,
	&intel_bdx_unc_cb12_support,
	&intel_bdx_unc_cb13_support,
	&intel_bdx_unc_cb14_support,
	&intel_bdx_unc_cb15_support,
	&intel_bdx_unc_cb16_support,
	&intel_bdx_unc_cb17_support,
	&intel_bdx_unc_cb18_support,
	&intel_bdx_unc_cb19_support,
	&intel_bdx_unc_cb20_support,
	&intel_bdx_unc_cb21_support,
	&intel_bdx_unc_cb22_support,
	&intel_bdx_unc_cb23_support,
	&intel_bdx_unc_ubo_support,
	&intel_bdx_unc_sbo0_support,
	&intel_bdx_unc_sbo1_support,
	&intel_bdx_unc_sbo2_support,
	&intel_bdx_unc_sbo3_support,
	&intel_bdx_unc_ha0_support,
	&intel_bdx_unc_ha1_support,
	&intel_bdx_unc_imc0_support,
	&intel_bdx_unc_imc1_support,
	&intel_bdx_unc_imc2_support,
	&intel_bdx_unc_imc3_support,
	&intel_bdx_unc_imc4_support,
	&intel_bdx_unc_imc5_support,
	&intel_bdx_unc_imc6_support,
	&intel_bdx_unc_imc7_support,
	&intel_bdx_unc_irp_support,
	&intel_bdx_unc_pcu_support,
	&intel_bdx_unc_qpi0_support,
	&intel_bdx_unc_qpi1_support,
	&intel_bdx_unc_qpi2_support,
	&intel_bdx_unc_r2pcie_support,
	&intel_bdx_unc_r3qpi0_support,
	&intel_bdx_unc_r3qpi1_support,
	&intel_bdx_unc_r3qpi2_support,
	&intel_skx_unc_cha0_support,
	&intel_skx_unc_cha1_support,
	&intel_skx_unc_cha2_support,
	&intel_skx_unc_cha3_support,
	&intel_skx_unc_cha4_support,
	&intel_skx_unc_cha5_support,
	&intel_skx_unc_cha6_support,
	&intel_skx_unc_cha7_support,
	&intel_skx_unc_cha8_support,
	&intel_skx_unc_cha9_support,
	&intel_skx_unc_cha10_support,
	&intel_skx_unc_cha11_support,
	&intel_skx_unc_cha12_support,
	&intel_skx_unc_cha13_support,
	&intel_skx_unc_cha14_support,
	&intel_skx_unc_cha15_support,
	&intel_skx_unc_cha16_support,
	&intel_skx_unc_cha17_support,
	&intel_skx_unc_cha18_support,
	&intel_skx_unc_cha19_support,
	&intel_skx_unc_cha20_support,
	&intel_skx_unc_cha21_support,
	&intel_skx_unc_cha22_support,
	&intel_skx_unc_cha23_support,
	&intel_skx_unc_cha24_support,
	&intel_skx_unc_cha25_support,
	&intel_skx_unc_cha26_support,
	&intel_skx_unc_cha27_support,
	&intel_skx_unc_iio0_support,
	&intel_skx_unc_iio1_support,
	&intel_skx_unc_iio2_support,
	&intel_skx_unc_iio3_support,
	&intel_skx_unc_iio4_support,
	&intel_skx_unc_iio5_support,
	&intel_skx_unc_imc0_support,
	&intel_skx_unc_imc1_support,
	&intel_skx_unc_imc2_support,
	&intel_skx_unc_imc3_support,
	&intel_skx_unc_imc4_support,
	&intel_skx_unc_imc5_support,
	&intel_skx_unc_pcu_support,
	&intel_skx_unc_upi0_support,
	&intel_skx_unc_upi1_support,
	&intel_skx_unc_upi2_support,
	&intel_skx_unc_m2m0_support,
	&intel_skx_unc_m2m1_support,
	&intel_skx_unc_ubo_support,
	&intel_skx_unc_m3upi0_support,
	&intel_skx_unc_m3upi1_support,
	&intel_skx_unc_m3upi2_support,
	&intel_skx_unc_irp_support,
	&intel_knm_support,
	&intel_knm_unc_imc0_support,
	&intel_knm_unc_imc1_support,
	&intel_knm_unc_imc2_support,
	&intel_knm_unc_imc3_support,
	&intel_knm_unc_imc4_support,
	&intel_knm_unc_imc5_support,
	&intel_knm_unc_imc_uclk0_support,
	&intel_knm_unc_imc_uclk1_support,
	&intel_knm_unc_edc_uclk0_support,
	&intel_knm_unc_edc_uclk1_support,
	&intel_knm_unc_edc_uclk2_support,
	&intel_knm_unc_edc_uclk3_support,
	&intel_knm_unc_edc_uclk4_support,
	&intel_knm_unc_edc_uclk5_support,
	&intel_knm_unc_edc_uclk6_support,
	&intel_knm_unc_edc_uclk7_support,
	&intel_knm_unc_edc_eclk0_support,
	&intel_knm_unc_edc_eclk1_support,
	&intel_knm_unc_edc_eclk2_support,
	&intel_knm_unc_edc_eclk3_support,
	&intel_knm_unc_edc_eclk4_support,
	&intel_knm_unc_edc_eclk5_support,
	&intel_knm_unc_edc_eclk6_support,
	&intel_knm_unc_edc_eclk7_support,
	&intel_knm_unc_cha0_support,
	&intel_knm_unc_cha1_support,
	&intel_knm_unc_cha2_support,
	&intel_knm_unc_cha3_support,
	&intel_knm_unc_cha4_support,
	&intel_knm_unc_cha5_support,
	&intel_knm_unc_cha6_support,
	&intel_knm_unc_cha7_support,
	&intel_knm_unc_cha8_support,
	&intel_knm_unc_cha9_support,
	&intel_knm_unc_cha10_support,
	&intel_knm_unc_cha11_support,
	&intel_knm_unc_cha12_support,
	&intel_knm_unc_cha13_support,
	&intel_knm_unc_cha14_support,
	&intel_knm_unc_cha15_support,
	&intel_knm_unc_cha16_support,
	&intel_knm_unc_cha17_support,
	&intel_knm_unc_cha18_support,
	&intel_knm_unc_cha19_support,
	&intel_knm_unc_cha20_support,
	&intel_knm_unc_cha21_support,
	&intel_knm_unc_cha22_support,
	&intel_knm_unc_cha23_support,
	&intel_knm_unc_cha24_support,
	&intel_knm_unc_cha25_support,
	&intel_knm_unc_cha26_support,
	&intel_knm_unc_cha27_support,
	&intel_knm_unc_cha28_support,
	&intel_knm_unc_cha29_support,
	&intel_knm_unc_cha30_support,
	&intel_knm_unc_cha31_support,
	&intel_knm_unc_cha32_support,
	&intel_knm_unc_cha33_support,
	&intel_knm_unc_cha34_support,
	&intel_knm_unc_cha35_support,
	&intel_knm_unc_cha36_support,
	&intel_knm_unc_cha37_support,
	&intel_knm_unc_m2pcie_support,
	&intel_x86_arch_support, /* must always be last for x86 */
#endif

#ifdef CONFIG_PFMLIB_ARCH_MIPS
	&mips_74k_support,
#endif

#ifdef CONFIG_PFMLIB_ARCH_SICORTEX
	&sicortex_support,
#endif

#ifdef CONFIG_PFMLIB_ARCH_POWERPC
	&power4_support,
	&ppc970_support,
	&ppc970mp_support,
	&power5_support,
	&power5p_support,
	&power6_support,
	&power7_support,
	&power8_support,
	&power9_support,
	&power10_support,
	&torrent_support,
    &powerpc_nest_mcs_read_support,
    &powerpc_nest_mcs_write_support,
#endif

#ifdef CONFIG_PFMLIB_ARCH_SPARC
	&sparc_ultra12_support,
	&sparc_ultra3_support,
	&sparc_ultra3i_support,
	&sparc_ultra3plus_support,
	&sparc_ultra4plus_support,
	&sparc_niagara1_support,
	&sparc_niagara2_support,
#endif

#ifdef CONFIG_PFMLIB_CELL
	&cell_support,
#endif

#ifdef CONFIG_PFMLIB_ARCH_ARM
	&arm_cortex_a7_support,
	&arm_cortex_a8_support,
	&arm_cortex_a9_support,
	&arm_cortex_a15_support,
	&arm_1176_support,
	&arm_qcom_krait_support,
	&arm_cortex_a57_support,
	&arm_cortex_a53_support,
	&arm_xgene_support,
	&arm_thunderx2_support,
	&arm_thunderx2_dmc0_support,
	&arm_thunderx2_dmc1_support,
	&arm_thunderx2_llc0_support,
	&arm_thunderx2_llc1_support,
	&arm_thunderx2_ccpi0_support,
	&arm_thunderx2_ccpi1_support,
	&arm_n1_support,
	&arm_n2_support,
	&arm_v1_support,
	&arm_v2_support,
	&arm_hisilicon_kunpeng_support,
	&arm_hisilicon_kunpeng_sccl1_ddrc0_support,
	&arm_hisilicon_kunpeng_sccl1_ddrc1_support,
	&arm_hisilicon_kunpeng_sccl1_ddrc2_support,
	&arm_hisilicon_kunpeng_sccl1_ddrc3_support,
	&arm_hisilicon_kunpeng_sccl3_ddrc0_support,
	&arm_hisilicon_kunpeng_sccl3_ddrc1_support,
	&arm_hisilicon_kunpeng_sccl3_ddrc2_support,
	&arm_hisilicon_kunpeng_sccl3_ddrc3_support,
	&arm_hisilicon_kunpeng_sccl5_ddrc0_support,
	&arm_hisilicon_kunpeng_sccl5_ddrc1_support,
	&arm_hisilicon_kunpeng_sccl5_ddrc2_support,
	&arm_hisilicon_kunpeng_sccl5_ddrc3_support,
	&arm_hisilicon_kunpeng_sccl7_ddrc0_support,
	&arm_hisilicon_kunpeng_sccl7_ddrc1_support,
	&arm_hisilicon_kunpeng_sccl7_ddrc2_support,
	&arm_hisilicon_kunpeng_sccl7_ddrc3_support,
	&arm_hisilicon_kunpeng_sccl1_hha2_support,
	&arm_hisilicon_kunpeng_sccl1_hha3_support,
	&arm_hisilicon_kunpeng_sccl3_hha0_support,
	&arm_hisilicon_kunpeng_sccl3_hha1_support,
	&arm_hisilicon_kunpeng_sccl5_hha6_support,
	&arm_hisilicon_kunpeng_sccl5_hha7_support,
	&arm_hisilicon_kunpeng_sccl7_hha4_support,
	&arm_hisilicon_kunpeng_sccl7_hha5_support,
	&arm_hisilicon_kunpeng_sccl1_l3c10_support,
	&arm_hisilicon_kunpeng_sccl1_l3c11_support,
	&arm_hisilicon_kunpeng_sccl1_l3c12_support,
	&arm_hisilicon_kunpeng_sccl1_l3c13_support,
	&arm_hisilicon_kunpeng_sccl1_l3c14_support,
	&arm_hisilicon_kunpeng_sccl1_l3c15_support,
	&arm_hisilicon_kunpeng_sccl1_l3c8_support,
	&arm_hisilicon_kunpeng_sccl1_l3c9_support,
	&arm_hisilicon_kunpeng_sccl3_l3c0_support,
	&arm_hisilicon_kunpeng_sccl3_l3c1_support,
	&arm_hisilicon_kunpeng_sccl3_l3c2_support,
	&arm_hisilicon_kunpeng_sccl3_l3c3_support,
	&arm_hisilicon_kunpeng_sccl3_l3c4_support,
	&arm_hisilicon_kunpeng_sccl3_l3c5_support,
	&arm_hisilicon_kunpeng_sccl3_l3c6_support,
	&arm_hisilicon_kunpeng_sccl3_l3c7_support,
	&arm_hisilicon_kunpeng_sccl5_l3c24_support,
	&arm_hisilicon_kunpeng_sccl5_l3c25_support,
	&arm_hisilicon_kunpeng_sccl5_l3c26_support,
	&arm_hisilicon_kunpeng_sccl5_l3c27_support,
	&arm_hisilicon_kunpeng_sccl5_l3c28_support,
	&arm_hisilicon_kunpeng_sccl5_l3c29_support,
	&arm_hisilicon_kunpeng_sccl5_l3c30_support,
	&arm_hisilicon_kunpeng_sccl5_l3c31_support,
	&arm_hisilicon_kunpeng_sccl7_l3c16_support,
	&arm_hisilicon_kunpeng_sccl7_l3c17_support,
	&arm_hisilicon_kunpeng_sccl7_l3c18_support,
	&arm_hisilicon_kunpeng_sccl7_l3c19_support,
	&arm_hisilicon_kunpeng_sccl7_l3c20_support,
	&arm_hisilicon_kunpeng_sccl7_l3c21_support,
	&arm_hisilicon_kunpeng_sccl7_l3c22_support,
	&arm_hisilicon_kunpeng_sccl7_l3c23_support,
#endif
#ifdef CONFIG_PFMLIB_ARCH_ARM64
	&arm_cortex_a57_support,
	&arm_cortex_a53_support,
	&arm_xgene_support,
	&arm_thunderx2_support,
	&arm_thunderx2_dmc0_support,
	&arm_thunderx2_dmc1_support,
	&arm_thunderx2_llc0_support,
	&arm_thunderx2_llc1_support,
	&arm_thunderx2_ccpi0_support,
	&arm_thunderx2_ccpi1_support,
	&arm_fujitsu_a64fx_support,
	&arm_hisilicon_kunpeng_sccl1_ddrc0_support,
	&arm_hisilicon_kunpeng_sccl1_ddrc1_support,
	&arm_hisilicon_kunpeng_sccl1_ddrc2_support,
	&arm_hisilicon_kunpeng_sccl1_ddrc3_support,
	&arm_hisilicon_kunpeng_sccl3_ddrc0_support,
	&arm_hisilicon_kunpeng_sccl3_ddrc1_support,
	&arm_hisilicon_kunpeng_sccl3_ddrc2_support,
	&arm_hisilicon_kunpeng_sccl3_ddrc3_support,
	&arm_hisilicon_kunpeng_sccl5_ddrc0_support,
	&arm_hisilicon_kunpeng_sccl5_ddrc1_support,
	&arm_hisilicon_kunpeng_sccl5_ddrc2_support,
	&arm_hisilicon_kunpeng_sccl5_ddrc3_support,
	&arm_hisilicon_kunpeng_sccl7_ddrc0_support,
	&arm_hisilicon_kunpeng_sccl7_ddrc1_support,
	&arm_hisilicon_kunpeng_sccl7_ddrc2_support,
	&arm_hisilicon_kunpeng_sccl7_ddrc3_support,
	&arm_hisilicon_kunpeng_sccl1_hha2_support,
	&arm_hisilicon_kunpeng_sccl1_hha3_support,
	&arm_hisilicon_kunpeng_sccl3_hha0_support,
	&arm_hisilicon_kunpeng_sccl3_hha1_support,
	&arm_hisilicon_kunpeng_sccl5_hha6_support,
	&arm_hisilicon_kunpeng_sccl5_hha7_support,
	&arm_hisilicon_kunpeng_sccl7_hha4_support,
	&arm_hisilicon_kunpeng_sccl7_hha5_support,
	&arm_hisilicon_kunpeng_sccl1_l3c10_support,
	&arm_hisilicon_kunpeng_sccl1_l3c11_support,
	&arm_hisilicon_kunpeng_sccl1_l3c12_support,
	&arm_hisilicon_kunpeng_sccl1_l3c13_support,
	&arm_hisilicon_kunpeng_sccl1_l3c14_support,
	&arm_hisilicon_kunpeng_sccl1_l3c15_support,
	&arm_hisilicon_kunpeng_sccl1_l3c8_support,
	&arm_hisilicon_kunpeng_sccl1_l3c9_support,
	&arm_hisilicon_kunpeng_sccl3_l3c0_support,
	&arm_hisilicon_kunpeng_sccl3_l3c1_support,
	&arm_hisilicon_kunpeng_sccl3_l3c2_support,
	&arm_hisilicon_kunpeng_sccl3_l3c3_support,
	&arm_hisilicon_kunpeng_sccl3_l3c4_support,
	&arm_hisilicon_kunpeng_sccl3_l3c5_support,
	&arm_hisilicon_kunpeng_sccl3_l3c6_support,
	&arm_hisilicon_kunpeng_sccl3_l3c7_support,
	&arm_hisilicon_kunpeng_sccl5_l3c24_support,
	&arm_hisilicon_kunpeng_sccl5_l3c25_support,
	&arm_hisilicon_kunpeng_sccl5_l3c26_support,
	&arm_hisilicon_kunpeng_sccl5_l3c27_support,
	&arm_hisilicon_kunpeng_sccl5_l3c28_support,
	&arm_hisilicon_kunpeng_sccl5_l3c29_support,
	&arm_hisilicon_kunpeng_sccl5_l3c30_support,
	&arm_hisilicon_kunpeng_sccl5_l3c31_support,
	&arm_hisilicon_kunpeng_sccl7_l3c16_support,
	&arm_hisilicon_kunpeng_sccl7_l3c17_support,
	&arm_hisilicon_kunpeng_sccl7_l3c18_support,
	&arm_hisilicon_kunpeng_sccl7_l3c19_support,
	&arm_hisilicon_kunpeng_sccl7_l3c20_support,
	&arm_hisilicon_kunpeng_sccl7_l3c21_support,
	&arm_hisilicon_kunpeng_sccl7_l3c22_support,
	&arm_hisilicon_kunpeng_sccl7_l3c23_support,
	&arm_n1_support,
	&arm_n2_support,
	&arm_v1_support,
	&arm_v2_support,
	&arm_hisilicon_kunpeng_support,
#endif

#ifdef CONFIG_PFMLIB_ARCH_S390X
	&s390x_cpum_cf_support,
	&s390x_cpum_sf_support,
#endif
#ifdef __linux__
	&perf_event_support,
	&perf_event_raw_support,
#endif
};
#define PFMLIB_NUM_PMUS	(int)(sizeof(pfmlib_pmus)/sizeof(pfmlib_pmu_t *))

static pfmlib_os_t pfmlib_os_none;
pfmlib_os_t *pfmlib_os = &pfmlib_os_none;

static pfmlib_os_t *pfmlib_oses[]={
	&pfmlib_os_none,
#ifdef __linux__
	&pfmlib_os_perf,
	&pfmlib_os_perf_ext,
#endif
};
#define PFMLIB_NUM_OSES	(int)(sizeof(pfmlib_oses)/sizeof(pfmlib_os_t *))

/*
 * Mapping table from PMU index to pfmlib_pmu_t
 * table is populated from pfmlib_pmus[] when the library
 * is initialized.
 *
 * Some entries can be NULL if PMU is not implemented on host
 * architecture or if the initialization failed.
 */
static pfmlib_pmu_t *pfmlib_pmus_map[PFM_PMU_MAX];
static pfmlib_node_t pfmlib_active_pmus_list;

/*
 * A drop-in replacement for strsep(). strsep() is not part of the POSIX
 * standard, and it is not available on all platforms - in particular it is not
 * provided by Microsoft's C runtime or by MinGW.
 */
static char* pfmlib_strsep(char **stringp, const char *delim)
{
	char* token = *stringp;
	char* end = *stringp;

	if (!end)
		return NULL;

	while (*end && !strchr(delim, *end))
		end++;

	if (*end) {
		*end = '\0';
		*stringp = end + 1;
	} else {
		*stringp = NULL;
	}
	return token;
}

#define pfmlib_for_each_pmu_event(p, e) \
	for(e=(p)->get_event_first((p)); e != -1; e = (p)->get_event_next((p), e))

#define for_each_pmu_event_attr(u, i) \
	for((u)=0; (u) < (i)->nattrs; (u) = (u)+1)

#define pfmlib_for_each_pmu(x) \
	for((x)= 0 ; (x) < PFMLIB_NUM_PMUS; (x)++)

#define pfmlib_for_each_pmu(x) \
	for((x)= 0 ; (x) < PFMLIB_NUM_PMUS; (x)++)

#define pfmlib_for_each_node(list, n) \
	for((n) = (list)->next; (list) != (n) ; (n) = (n)->next)

#define pfmlib_for_each_os(x) \
	for((x)= 0 ; (x) < PFMLIB_NUM_OSES; (x)++)

pfmlib_config_t pfm_cfg;

static inline pfmlib_pmu_t *
pfmlib_node_to_pmu(pfmlib_node_t *n)
{
	void *p = (void *)n;
	void *offs = (void *)offsetof(pfmlib_pmu_t, node);
	return (pfmlib_pmu_t *)(p - offs);
}

void
__pfm_dbprintf(const char *fmt, ...)
{
	va_list ap;

	if (pfm_cfg.debug == 0)
		return;

	va_start(ap, fmt);
	vfprintf(pfm_cfg.fp, fmt, ap);
	va_end(ap);
}

void
__pfm_vbprintf(const char *fmt, ...)
{
	va_list ap;

	if (pfm_cfg.verbose == 0)
		return;

	va_start(ap, fmt);
	vfprintf(pfm_cfg.fp, fmt, ap);
	va_end(ap);
}

/*
 * pfmlib_getl: our own equivalent to GNU getline() extension.
 * This avoids a dependency on having a C library with
 * support for getline().
 */
int
pfmlib_getl(char **buffer, size_t *len, FILE *fp)
{
#define	GETL_DFL_LEN	32
	char *b;
	int c;
	size_t maxsz, maxi, d, i = 0;

	if (!len || !fp || !buffer || (*buffer && *len < 2))
		return -1;

	b = *buffer;

	if (!b)
		*len = 0;

	maxsz = *len;
	maxi = maxsz - 2;

	while ((c = fgetc(fp)) != EOF) {
		if (maxsz == 0 || i == maxi) {
			if (maxsz == 0)
				maxsz = GETL_DFL_LEN;
			else
				maxsz <<= 1;

			if (*buffer)
				d = &b[i] - *buffer;
			else
				d = 0;

			*buffer = realloc(*buffer, maxsz);
			if (!*buffer)
				return -1;

			b = *buffer + d;
			maxi = maxsz - d - 2;
			i = 0;
			*len = maxsz;
		}
		b[i++] = c;
		if (c == '\n')
			break;
	}
	b[i] = '\0';
	return c != EOF ? 0 : -1;
}



/*
 * append fmt+args to str such that the string is no
 * more than max characters incl. null termination
 */
void
pfmlib_strconcat(char *str, size_t max, const char *fmt, ...)
{
	va_list ap;
	size_t len, todo;

	len = strlen(str);
	todo = max - strlen(str);
	va_start(ap, fmt);
	vsnprintf(str+len, todo, fmt, ap);
	va_end(ap);
}

/*
 * compact all pattrs starting from index i
 */
void
pfmlib_compact_pattrs(pfmlib_event_desc_t *e, int i)
{
	int j;

	for (j = i+1; j < e->npattrs; j++)
		e->pattrs[j - 1] = e->pattrs[j];

	e->npattrs--;
}

static void
pfmlib_compact_attrs(pfmlib_event_desc_t *e, int i)
{
	int j;

	for (j = i+1; j < e->nattrs; j++)
		e->attrs[j - 1] = e->attrs[j];

	e->nattrs--;
}

/*
 *  0 : different attribute
 *  1 : exactly same attribute (duplicate can be removed)
 * -1 : same attribute but value differ, this is an error
 */
static inline int
pfmlib_same_attr(pfmlib_event_desc_t *d, int i, int j)
{
	pfmlib_event_attr_info_t *a1, *a2;
	pfmlib_attr_t *b1, *b2;

	a1 = attr(d, i);
	a2 = attr(d, j);

	b1 = d->attrs+i;
	b2 = d->attrs+j;

	if (a1->idx == a2->idx
	    && a1->type == a2->type
	    && a1->ctrl == a2->ctrl) {
		if (b1->ival == b2->ival)
			return 1;
		return -1;

	}
	return 0;
}

static inline int
pfmlib_pmu_active(pfmlib_pmu_t *pmu)
{
        return !!(pmu->flags & PFMLIB_PMU_FL_ACTIVE);
}

static inline int
pfmlib_pmu_deprecated(pfmlib_pmu_t *pmu)
{
        return !!(pmu->flags & PFMLIB_PMU_FL_DEPR);
}

static inline int
pfmlib_pmu_initialized(pfmlib_pmu_t *pmu)
{
        return !!(pmu->flags & PFMLIB_PMU_FL_INIT);
}

static inline pfm_pmu_t
idx2pmu(int idx)
{
	return (pfm_pmu_t)((idx >> PFMLIB_PMU_SHIFT) & PFMLIB_PMU_MASK);
}

static inline pfmlib_pmu_t *
pmu2pmuidx(pfm_pmu_t pmu)
{
	/* pfm_pmu_t is unsigned int enum, so
	 * just need to check for upper bound
	 */
	if (pmu >= PFM_PMU_MAX)
		return NULL;

	return pfmlib_pmus_map[pmu];
}

/*
 * external opaque idx -> PMU + internal idx
 */
static pfmlib_pmu_t *
pfmlib_idx2pidx(int idx, int *pidx)
{
	pfmlib_pmu_t *pmu;
	pfm_pmu_t pmu_id;

	if (PFMLIB_INITIALIZED() == 0)
		return NULL;

	if (idx < 0)
		return NULL;

	pmu_id = idx2pmu(idx);

	pmu = pmu2pmuidx(pmu_id);
	if (!pmu)
		return NULL;

	*pidx = idx & PFMLIB_PMU_PIDX_MASK;

	if (!pmu->event_is_valid(pmu, *pidx))
		return NULL;

	return pmu;
}

static pfmlib_os_t *
pfmlib_find_os(pfm_os_t id)
{
	int o;
	pfmlib_os_t *os;

	pfmlib_for_each_os(o) {
		os = pfmlib_oses[o];
		if (os->id == id && (os->flags & PFMLIB_OS_FL_ACTIVATED))
			return os;
	}
	return NULL;
}

size_t
pfmlib_check_struct(void *st, size_t usz, size_t refsz, size_t sz)
{
	size_t rsz = sz;

	/*
	 * if user size is zero, then use ABI0 size
	 */
	if (usz == 0)
		usz = refsz;

	/*
	 * cannot be smaller than ABI0 size
	 */
	if (usz < refsz) {
		DPRINT("pfmlib_check_struct: user size too small %zu\n", usz);
		return 0;
	}

	/*
	 * if bigger than current ABI, then check that none
	 * of the extra bits are set. This is to avoid mistake
	 * by caller assuming the library set those bits.
	 */
	if (usz > sz) {
		char *addr = (char *)st + sz;
		char *end = (char *)st + usz;
		while (addr != end) {
			if (*addr++) {
				DPRINT("pfmlib_check_struct: invalid extra bits\n");
				return 0;
			}
		}
	}
	return rsz;
}

/*
 * check environment variables for:
 *  LIBPFM_VERBOSE : enable verbose output (must be 1)
 *  LIBPFM_DEBUG   : enable debug output (must be 1)
 */
static void
pfmlib_init_env(void)
{
	char *str;

	pfm_cfg.fp = stderr;

	str = getenv("LIBPFM_VERBOSE");
	if (str && isdigit((int)*str))
		pfm_cfg.verbose = *str - '0';

	str = getenv("LIBPFM_DEBUG");
	if (str && isdigit((int)*str))
		pfm_cfg.debug = *str - '0';

	str = getenv("LIBPFM_DEBUG_STDOUT");
	if (str)
		pfm_cfg.fp = stdout;

	pfm_cfg.forced_pmu = getenv("LIBPFM_FORCE_PMU");

	str = getenv("LIBPFM_ENCODE_INACTIVE");
	if (str && isdigit((int)*str))
		pfm_cfg.inactive = *str - '0';

	str = getenv("LIBPFM_DISABLED_PMUS");
	if (str)
		pfm_cfg.blacklist_pmus = str;
}

static int
pfmlib_pmu_sanity_checks(pfmlib_pmu_t *p)
{
	/*
	 * check event can be encoded
	 */
	if (p->pme_count >= (1<< PFMLIB_PMU_SHIFT)) {
		DPRINT("too many events for %s\n", p->desc);
		return PFM_ERR_NOTSUPP;
	}

	if (p->max_encoding > PFMLIB_MAX_ENCODING) {
		DPRINT("max encoding too high (%d > %d) for %s\n",
			p->max_encoding, PFMLIB_MAX_ENCODING, p->desc);
		return PFM_ERR_NOTSUPP;
	}

	return PFM_SUCCESS;
}

int
pfmlib_build_fstr(pfmlib_event_desc_t *e, char **fstr)
{
	/* nothing to do */
	if (!fstr)
		return PFM_SUCCESS;

	*fstr = malloc(strlen(e->fstr) + 2 + strlen(e->pmu->name) + 1);
	if (*fstr)
		sprintf(*fstr, "%s::%s", e->pmu->name, e->fstr);

	return *fstr ? PFM_SUCCESS : PFM_ERR_NOMEM;
}

static int
pfmlib_pmu_activate(pfmlib_pmu_t *p)
{
	int ret;

	if (p->pmu_init) {
		ret = p->pmu_init(p);
		if (ret != PFM_SUCCESS)
			return ret;
	}

	p->flags |= PFMLIB_PMU_FL_ACTIVE;

	DPRINT("activated %s\n", p->desc);

	return PFM_SUCCESS;
}

static inline int
pfmlib_match_forced_pmu(const char *name)
{
	const char *p;
	size_t l;

	/* skip any lower level specifier */
	p = strchr(pfm_cfg.forced_pmu, ',');
	if (p)
		l = p - pfm_cfg.forced_pmu;
	else
		l = strlen(pfm_cfg.forced_pmu);

	return !strncasecmp(name, pfm_cfg.forced_pmu, l);
}

static int
pfmlib_is_blacklisted_pmu(pfmlib_pmu_t *p)
{
	char *q, *buffer;
	int ret = 1;

	if (!pfm_cfg.blacklist_pmus)
		return 0;

	/*
	 * scan list for matching PMU names, we accept substrings.
	 * for instance: snbep does match snbep*
	 */
	buffer = strdup(pfm_cfg.blacklist_pmus);
	if (!buffer)
		return 0;

	strcpy (buffer, pfm_cfg.blacklist_pmus);
	for (q = strtok (buffer, ","); q != NULL; q = strtok (NULL, ",")) {
		if (strstr (p->name, q) != NULL) {
			goto done;
		}
	}
	ret = 0;
done:
	free(buffer);
	return ret;
}

static inline void
pfmlib_node_init(pfmlib_node_t *n)
{
	n->next = n->prev = n;
}

static inline void
pfmlib_node_add_tail(pfmlib_node_t *list, pfmlib_node_t *n)
{
	n->prev = list->prev;
	n->next = list;

	list->prev->next = n;
	list->prev = n;
}

static inline void
pfmlib_add_active_pmu(pfmlib_pmu_t *pmu)
{
	/*
	 * We must append to tail of the list to respect the ordering
	 * of the PMUs in the pfmlib_pmus[] array as the order matters.
	 * For instance, on Intel x86 there is an architected PMU to
	 * catch default events and it needs to be checked last to
	 * give priority to model specific event encodings
	 */
	pfmlib_node_add_tail(&pfmlib_active_pmus_list, &pmu->node);
}

static int
pfmlib_init_pmus(void)
{
	pfmlib_pmu_t *p;
	int i, ret;
	int nsuccess = 0;
	
	/*
	 * activate all detected PMUs
	 * when forced, only the designated PMU
	 * is setup and activated
	 */
	pfmlib_for_each_pmu(i) {

		p = pfmlib_pmus[i];

		DPRINT("trying %s\n", p->desc);

		ret = PFM_SUCCESS;

		if (!pfm_cfg.forced_pmu)
			ret = p->pmu_detect(p);
		else if (!pfmlib_match_forced_pmu(p->name))
			ret = PFM_ERR_NOTSUPP;

		/*
		 * basic checks
		 * failure causes PMU to not be available
		 */
		if (pfmlib_pmu_sanity_checks(p) != PFM_SUCCESS)
			continue;

		if (pfmlib_is_blacklisted_pmu(p)) {
			DPRINT("%s PMU blacklisted, skipping initialization\n", p->name);
			continue;
		}
		p->flags |= PFMLIB_PMU_FL_INIT;

		/*
		 * populate mapping table
		 */
		pfmlib_pmus_map[p->pmu] = p;

		if (ret != PFM_SUCCESS) {
			/*
			 * if LIBPFM_ENCODE_INACTIVE=1, we place all PMUs on the active list.
			 * we lose the optimization but we do not have to special case the parsing
			 * code. This is a debug option anyway.
			 */
			if (pfm_cfg.inactive)
				pfmlib_add_active_pmu(p);
			continue;
		}

		/*
		 * check if exported by OS if needed
		 */
		if (p->os_detect[pfmlib_os->id]) {
			ret = p->os_detect[pfmlib_os->id](p);
			if (ret != PFM_SUCCESS) {
				/*
				 * must force on active list when
				 * LIBPFM_ENCODE_INACTIVE=1
				 */
				if (pfm_cfg.inactive)
					pfmlib_add_active_pmu(p);
				DPRINT("%s PMU not exported by OS\n", p->name);
				continue;
			}
		}

		ret = pfmlib_pmu_activate(p);
		if (ret == PFM_SUCCESS) {
			nsuccess++;
			pfmlib_add_active_pmu(p);
		}

		if (pfm_cfg.forced_pmu) {
			__pfm_vbprintf("PMU forced to %s (%s) : %s\n",
					p->name,
					p->desc,
					ret == PFM_SUCCESS ? "success" : "failure");
			return ret;
		}
	}
	DPRINT("%d PMU detected out of %d supported\n", nsuccess, PFMLIB_NUM_PMUS);
	return PFM_SUCCESS;
}

static void
pfmlib_init_os(void)
{
	int o;
	pfmlib_os_t *os;

	pfmlib_for_each_os(o) {
		os = pfmlib_oses[o];

		if (!os->detect)
			continue;

		if (os->detect(os) != PFM_SUCCESS)
			continue;

		if (os != &pfmlib_os_none && pfmlib_os == &pfmlib_os_none)
			pfmlib_os = os;

		DPRINT("OS layer %s activated\n", os->name);
		os->flags = PFMLIB_OS_FL_ACTIVATED;
	}
	DPRINT("default OS layer: %s\n", pfmlib_os->name);
}

int
pfm_initialize(void)
{
	int ret;
	/*
	 * not atomic
	 * if initialization already done, then reurn previous return value
	 */
	if (pfm_cfg.initdone)
		return pfm_cfg.initret;

	pfmlib_node_init(&pfmlib_active_pmus_list);

	/*
	 * generic sanity checks
	 */
	if (PFM_PMU_MAX & (~PFMLIB_PMU_MASK)) {
		DPRINT("PFM_PMU_MAX exceeds PFMLIB_PMU_MASK\n");	
		ret = PFM_ERR_NOTSUPP;
	} else {

		pfmlib_init_env();

		/* must be done before pfmlib_init_pmus() */
		pfmlib_init_os();

		ret = pfmlib_init_pmus();
	}

	pfm_cfg.initdone = 1;
	pfm_cfg.initret  = ret;

	return ret;
}

void
pfm_terminate(void)
{
	pfmlib_node_t *n;
	pfmlib_pmu_t *pmu;

	if (PFMLIB_INITIALIZED() == 0)
		return;

	pfmlib_for_each_node(&pfmlib_active_pmus_list, n) {
		pmu = pfmlib_node_to_pmu(n);

		/* handle LIBPFM_ENCODE_INACTIVE=1 */
		if (!pfmlib_pmu_active(pmu))
			continue;
		if (pmu->pmu_terminate)
			pmu->pmu_terminate(pmu);
	}
	pfm_cfg.initdone = 0;

	pfmlib_node_init(&pfmlib_active_pmus_list);
}

int
pfm_find_event(const char *str)
{
	pfmlib_event_desc_t e;
	int ret;

	if (PFMLIB_INITIALIZED() == 0)
		return PFM_ERR_NOINIT;

	if (!str)
		return PFM_ERR_INVAL;

	memset(&e, 0, sizeof(e));

	ret = pfmlib_parse_event(str, &e);
	if (ret == PFM_SUCCESS) {
		/*
		 * save index so we can return it
		 * and free the pattrs data that was
		 * allocated in pfmlib_parse_event()
		 */
		ret = pfmlib_pidx2idx(e.pmu, e.event);

		pfmlib_release_event(&e);
	}

	return ret;
}

static int
pfmlib_sanitize_event(pfmlib_event_desc_t *d)
{
	int i, j, ret;

	/*
	 * fail if duplicate attributes are found
	 */
	for(i=0; i < d->nattrs; i++) {
		for(j=i+1; j < d->nattrs; j++) {
			ret = pfmlib_same_attr(d, i, j);
			if (ret == 1)
				pfmlib_compact_attrs(d, j);
			else if (ret == -1)
				return PFM_ERR_ATTR_SET;
		}
	}
	return PFM_SUCCESS;
}

static int
pfmlib_parse_event_attr(char *str, pfmlib_event_desc_t *d)
{
	pfmlib_event_attr_info_t *ainfo;
	char *s, *p, *q, *endptr;
	char yes[2] = "y";
	pfm_attr_t type;
	int aidx = 0, has_val, has_raw_um = 0, has_um = 0;
	int ret = PFM_ERR_INVAL;

	s = str;

	while(s) {
	        p = s;
	        pfmlib_strsep(&p, PFMLIB_ATTR_DELIM);
		/* if (p)
		 *p++ = '\0'; */

		q = strchr(s, '=');
		if (q)
			*q++ = '\0';

		has_val = !!q;

		/*
		 * check for raw umasks in hexdecimal only
		 */
		if (*s == '0' && tolower(*(s+1)) == 'x') {
			char *endptr = NULL;

			/* can only have one raw umask */
			if (has_raw_um || has_um) {
				DPRINT("cannot mix raw umask with umask\n");
				return PFM_ERR_ATTR;
			}
			if (!(d->pmu->flags & PFMLIB_PMU_FL_RAW_UMASK)) {
				DPRINT("PMU %s does not support RAW umasks\n", d->pmu->name);
				return PFM_ERR_ATTR;
			}

			/* we have reserved an entry at the end of pattrs */
			aidx = d->npattrs;
			ainfo = d->pattrs + aidx;

			ainfo->name = "RAW_UMASK";
			ainfo->type = PFM_ATTR_RAW_UMASK;
			ainfo->ctrl = PFM_ATTR_CTRL_PMU;
			/* can handle up to 64-bit raw umask */
			ainfo->idx  = strtoull(s, &endptr, 0);
			ainfo->equiv= NULL;
			if (*endptr) {
				DPRINT("raw umask (%s) is not a number\n", str);
				return PFM_ERR_ATTR;
			}

			has_raw_um = 1;

			goto found_attr;
		}

		for(aidx = 0; aidx < d->npattrs; aidx++) {
			if (!strcasecmp(d->pattrs[aidx].name, s)) {
				ainfo = d->pattrs + aidx;
				/* disambiguate modifier and umask
				 * with the same name : snb::L2_LINES_IN:I:I=1
				 */
				if (has_val && ainfo->type == PFM_ATTR_UMASK)
					continue;
				goto found_attr;
			}
		}
		DPRINT("cannot find attribute %s\n", s);
		return PFM_ERR_ATTR;
found_attr:
		type = ainfo->type;

		if (type == PFM_ATTR_UMASK) {
			has_um = 1;
			if (has_raw_um) {
				DPRINT("cannot mix raw umask with umask\n");
				return PFM_ERR_ATTR;
			}
		}

		if (ainfo->equiv) {
			char *z;

			/* cannot have equiv for attributes with value */
			if (has_val)
				return PFM_ERR_ATTR_VAL;

			/* copy because it is const */
			z = strdup(ainfo->equiv);
			if (!z)
				return PFM_ERR_NOMEM;

			ret = pfmlib_parse_event_attr(z, d);

			free(z);

			if (ret != PFM_SUCCESS)
				return ret;
			s = p;
			continue;
		}
		/*
		 * we tolerate missing value for boolean attributes.
		 * Presence of the attribute is equivalent to
		 * attr=1, i.e., attribute is set
		 */
		if (type != PFM_ATTR_UMASK && type != PFM_ATTR_RAW_UMASK && !has_val) {
			if (type != PFM_ATTR_MOD_BOOL)
				return PFM_ERR_ATTR_VAL;
			s = yes; /* no const */
			goto handle_bool;
		}

		d->attrs[d->nattrs].ival = 0;
		if ((type == PFM_ATTR_UMASK || type == PFM_ATTR_RAW_UMASK) && has_val)
			return PFM_ERR_ATTR_VAL;

		if (has_val) {
			s = q;
handle_bool:
			ret = PFM_ERR_ATTR_VAL;
			if (!strlen(s))
				goto error;
			if (d->nattrs == PFMLIB_MAX_ATTRS) {
				DPRINT("too many attributes\n");
				ret = PFM_ERR_TOOMANY;
				goto error;
			}

			endptr = NULL;
			switch(type) {
			case PFM_ATTR_MOD_BOOL:
				if (strlen(s) > 1)
					goto error;

				if (tolower((int)*s) == 'y'
				    || tolower((int)*s) == 't' || *s == '1')
					d->attrs[d->nattrs].ival = 1;
				else if (tolower((int)*s) == 'n'
					 || tolower((int)*s) == 'f' || *s == '0')
					d->attrs[d->nattrs].ival = 0;
				else
					goto error;
				break;
			case PFM_ATTR_MOD_INTEGER:
				d->attrs[d->nattrs].ival = strtoull(s, &endptr, 0);
				if (*endptr != '\0')
					goto error;
				break;
			default:
				goto error;
			}
		}
		d->attrs[d->nattrs].id = aidx;
		d->nattrs++;
		s = p;
	}
	ret = PFM_SUCCESS;
error:
	return ret;
}

static int
pfmlib_build_event_pattrs(pfmlib_event_desc_t  *e)
{
	pfmlib_pmu_t *pmu;
	pfmlib_os_t *os;
	int i, ret, pmu_nattrs = 0, os_nattrs = 0;
	int npattrs;

	/*
	 * cannot satisfy request for an OS that was not activated
	 */
	os = pfmlib_find_os(e->osid);
	if (!os)
		return PFM_ERR_NOTSUPP;

	pmu = e->pmu;

	/* get actual PMU number of attributes for the event */
	if (pmu->get_event_nattrs)
		pmu_nattrs = pmu->get_event_nattrs(pmu, e->event);
	if (os && os->get_os_nattrs)
		os_nattrs += os->get_os_nattrs(os, e);

	npattrs = pmu_nattrs + os_nattrs;

	/*
	 * add extra entry for raw umask, if supported
	 */
	if (pmu->flags & PFMLIB_PMU_FL_RAW_UMASK)
		npattrs++;

	if (npattrs) {
		e->pattrs = calloc(npattrs, sizeof(*e->pattrs));
		if (!e->pattrs)
			return PFM_ERR_NOMEM;
	}

	/* collect all actual PMU attrs */
	for(i = 0; i < pmu_nattrs; i++) {
		ret = pmu->get_event_attr_info(pmu, e->event, i, e->pattrs+i);
		if (ret != PFM_SUCCESS)
			goto error;
	}
	e->npattrs = pmu_nattrs;

	if (os_nattrs) {
		if (e->osid == os->id && os->get_os_attr_info) {
			os->get_os_attr_info(os, e);
			/*
			 * check for conflicts between HW and OS attributes
			 */
			if (pmu->validate_pattrs[e->osid])
				pmu->validate_pattrs[e->osid](pmu, e);
		}
	}
	for (i = 0; i < e->npattrs; i++)
		DPRINT("%d %d %d %d %d %s\n", e->event, i, e->pattrs[i].type, e->pattrs[i].ctrl, e->pattrs[i].idx, e->pattrs[i].name);

	return PFM_SUCCESS;
error:
	free(e->pattrs);
	e->pattrs = NULL;
	return ret;
}

void
pfmlib_release_event(pfmlib_event_desc_t *e)
{
	free(e->pattrs);
	e->pattrs = NULL;
}

static int
match_event(void *this, pfmlib_event_desc_t *d, const char *e, const char *s)
{
	return strcasecmp(e, s);
}

static int
pfmlib_parse_equiv_event(const char *event, pfmlib_event_desc_t *d)
{
	pfmlib_pmu_t *pmu = d->pmu;
	pfm_event_info_t einfo;
	int (*match)(void *this, pfmlib_event_desc_t *d, const char *e, const char *s);
	char *str, *s, *p;
	int i;
	int ret;

	/*
	 * create copy because string is const
	 */
	s = str = strdup(event);
	if (!str)
		return PFM_ERR_NOMEM;

	p = s;
	pfmlib_strsep(&p, PFMLIB_ATTR_DELIM);
	/* if (p)
	 *p++ = '\0'; */

	match = pmu->match_event ? pmu->match_event : match_event;

	pfmlib_for_each_pmu_event(pmu, i) {
		ret = pmu->get_event_info(pmu, i, &einfo);
		if (ret != PFM_SUCCESS)
			goto error;
		if (!match(pmu, d, einfo.name, s))
			goto found;
	}
	free(str);
	return PFM_ERR_NOTFOUND;
found:
	d->pmu = pmu;
	d->event = i; /* private index */

	/*
	 * build_event_pattrs and parse_event_attr
	 * cannot be factorized with pfmlib_parse_event()
	 * because equivalent event may add its own attributes
	 */
	ret = pfmlib_build_event_pattrs(d);
	if (ret != PFM_SUCCESS)
		goto error;

	ret = pfmlib_parse_event_attr(p, d);
	if (ret == PFM_SUCCESS)
		ret = pfmlib_sanitize_event(d);
error:
	free(str);

	if (ret != PFM_SUCCESS)
		pfmlib_release_event(d);

	return ret;
}

int
pfmlib_parse_event(const char *event, pfmlib_event_desc_t *d)
{
	pfmlib_node_t *n;
	pfm_event_info_t einfo;
	char *str, *s, *p;
	pfmlib_pmu_t *pmu;
	int (*match)(void *this, pfmlib_event_desc_t *d, const char *e, const char *s);
	const char *pname = NULL;
	int i, ret;

	/*
	 * support only one event at a time.
	 */
	p = strpbrk(event, PFMLIB_EVENT_DELIM);
	if (p)
		return PFM_ERR_INVAL;
	/*
	 * create copy because string is const
	 */
	s = str = strdup(event);
	if (!str)
		return PFM_ERR_NOMEM;


	/* check for optional PMU name */
	p = strstr(s, PFMLIB_PMU_DELIM);
	if (p) {
		*p = '\0';
		pname = s;
		s = p + strlen(PFMLIB_PMU_DELIM);
	}
	p = s;
	pfmlib_strsep(&p, PFMLIB_ATTR_DELIM);
	/* if (p)
	 *p++ = '\0'; */

	/*
	 * for each pmu
	 */
	pfmlib_for_each_node(&pfmlib_active_pmus_list, n) {
		pmu = pfmlib_node_to_pmu(n);

		/*
		 * test against active still required in case of
		 * pfm_cfg.inactive=1 because we put all PMUs on
		 * the active list to avoid forking this loop
		 */
		if (!pname && !pfmlib_pmu_active(pmu))
			continue;
		/*
		 * if the PMU name is not passed, then if
		 * the pmu is deprecated, then skip it. It means
		 * there is a better candidate in the active list
		 */
		if (!pname && pfmlib_pmu_deprecated(pmu))
			continue;
		/*
		 * check for requested PMU name,
		 */
		if (pname && strcasecmp(pname, pmu->name))
			continue;
		/*
		 * only allow event on inactive PMU if enabled via
		 * environement variable
		 */
		if (pname && !pfmlib_pmu_active(pmu) && !pfm_cfg.inactive)
			continue;

		match = pmu->match_event ? pmu->match_event : match_event;
		/*
		 * for each event
		 */
		pfmlib_for_each_pmu_event(pmu, i) {
			ret = pmu->get_event_info(pmu, i, &einfo);
			if (ret != PFM_SUCCESS)
				goto error;
			if (!match(pmu, d, einfo.name, s))
				goto found;
		}
	}
	free(str);
	return PFM_ERR_NOTFOUND;
found:
	d->pmu = pmu;
	/*
	 * handle equivalence
	 */
	if (einfo.equiv) {
		ret = pfmlib_parse_equiv_event(einfo.equiv, d);
		if (ret != PFM_SUCCESS)
			goto error;
	} else {
		d->event = i; /* private index */

		ret = pfmlib_build_event_pattrs(d);
		if (ret != PFM_SUCCESS)
			goto error;
	}
	/*
	 * parse attributes from original event
	 */
	ret = pfmlib_parse_event_attr(p, d);
	if (ret == PFM_SUCCESS)
		ret = pfmlib_sanitize_event(d);

	for (i = 0; i < d->nattrs; i++) {
		pfmlib_event_attr_info_t *a = attr(d, i);
		if (a->type != PFM_ATTR_RAW_UMASK)
			DPRINT("%d %d %d %s\n", d->event, i, a->idx, d->pattrs[d->attrs[i].id].name);
		else
			DPRINT("%d %d RAW_UMASK (0x%x)\n", d->event, i, a->idx);
	}
error:
	free(str);
	if (ret != PFM_SUCCESS)
		pfmlib_release_event(d);
	return ret;
}

/* sorry, only English supported at this point! */
static const char *pfmlib_err_list[]=
{
	"success",
	"not supported",
	"invalid parameters",
	"pfmlib not initialized",
	"event not found",
	"invalid combination of model specific features",
	"invalid or missing unit mask",
	"out of memory",
	"invalid event attribute",
	"invalid event attribute value",
	"attribute value already set",
	"too many parameters",
	"parameter is too small",
};
static int pfmlib_err_count = (int)sizeof(pfmlib_err_list)/sizeof(char *);

const char *
pfm_strerror(int code)
{
	code = -code;
	if (code <0 || code >= pfmlib_err_count)
		return "unknown error code";

	return pfmlib_err_list[code];
}

int
pfm_get_version(void)
{
	return LIBPFM_VERSION;
}

int
pfm_get_event_next(int idx)
{
	pfmlib_pmu_t *pmu;
	int pidx;

	pmu = pfmlib_idx2pidx(idx, &pidx);
	if (!pmu)
		return -1;

	pidx = pmu->get_event_next(pmu, pidx);
	return pidx == -1 ? -1 : pfmlib_pidx2idx(pmu, pidx);
}

int
pfm_get_os_event_encoding(const char *str, int dfl_plm, pfm_os_t uos, void *args)
{
	pfmlib_os_t *os;

	if (PFMLIB_INITIALIZED() == 0)
		return PFM_ERR_NOINIT;

	if (!(args && str))
		return PFM_ERR_INVAL;

	if (dfl_plm & ~(PFM_PLM_ALL))
		return PFM_ERR_INVAL;

	os = pfmlib_find_os(uos);
	if (!os)
		return PFM_ERR_NOTSUPP;

	return os->encode(os, str, dfl_plm, args);
}

/*
 * old API maintained for backward compatibility with existing apps
 * prefer pfm_get_os_event_encoding()
 */
int
pfm_get_event_encoding(const char *str, int dfl_plm, char **fstr, int *idx, uint64_t **codes, int *count)
{
	pfm_pmu_encode_arg_t arg;
	int ret;

	if (!(str && codes && count))
		return PFM_ERR_INVAL;

	if ((*codes && !*count) || (!*codes && *count))
		return PFM_ERR_INVAL;

	memset(&arg, 0, sizeof(arg));

	arg.fstr = fstr;
	arg.codes = *codes;
	arg.count = *count;
	arg.size  = sizeof(arg);

	/*
	 * request RAW PMU encoding
	 */
	ret = pfm_get_os_event_encoding(str, dfl_plm, PFM_OS_NONE, &arg);
	if (ret != PFM_SUCCESS)
		return ret;

	/* handle the case where the array was allocated */
	*codes = arg.codes;
	*count = arg.count;

	if (idx)
		*idx = arg.idx;

	return PFM_SUCCESS;
}

static int
pfmlib_check_event_pattrs(pfmlib_pmu_t *pmu, int pidx, pfm_os_t osid, FILE *fp)
{
	pfmlib_event_desc_t e;
	int i, j, ret;

	memset(&e, 0, sizeof(e));
	e.event = pidx;
	e.osid  = osid;
	e.pmu   = pmu;

	ret = pfmlib_build_event_pattrs(&e);
	if (ret != PFM_SUCCESS) {
		fprintf(fp, "invalid pattrs for event %d\n", pidx);
		return ret;
	}

	ret = PFM_ERR_ATTR;

	for (i = 0; i < e.npattrs; i++) {
		for (j = i+1; j < e.npattrs; j++) {
			if (!strcmp(e.pattrs[i].name, e.pattrs[j].name)) {
				fprintf(fp, "event %d duplicate pattrs %s\n", pidx, e.pattrs[i].name);
				goto error;
			}
		}
	}
	ret = PFM_SUCCESS;
error:
	/*
	 * release resources allocated for event
	 */
	pfmlib_release_event(&e);
	return ret;
}

static int
pfmlib_validate_encoding(char *buf, int plm)
{
	uint64_t *codes = NULL;
	int count = 0, ret;

	ret = pfm_get_event_encoding(buf, plm, NULL, NULL, &codes, &count);
	if (ret != PFM_SUCCESS) {
		int i;
		DPRINT("%s ", buf);
		for(i=0; i < count; i++)
			__pfm_dbprintf(" %#"PRIx64, codes[i]);
		__pfm_dbprintf("\n");
	}
	if (codes)
		free(codes);

	return ret;
}

static int
pfmlib_pmu_validate_encoding(pfmlib_pmu_t *pmu, FILE *fp)
{
	pfm_event_info_t einfo;
	pfmlib_event_attr_info_t ainfo;
	char *buf;
	size_t maxlen = 0, len;
	int i, u, um;
	int ret, retval = PFM_SUCCESS;

	pfmlib_for_each_pmu_event(pmu, i) {
		ret = pmu->get_event_info(pmu, i, &einfo);
		if (ret != PFM_SUCCESS)
			return ret;

		ret = pfmlib_check_event_pattrs(pmu, i, PFM_OS_NONE, fp);
		if (ret != PFM_SUCCESS)
			return ret;

		len = strlen(einfo.name);
		if (len > maxlen)
			maxlen = len;

		for_each_pmu_event_attr(u, &einfo) {
			ret = pmu->get_event_attr_info(pmu, i, u, &ainfo);
			if (ret != PFM_SUCCESS)
				return ret;

			if (ainfo.type != PFM_ATTR_UMASK)
				continue;

			len = strlen(einfo.name) + strlen(ainfo.name);
			if (len > maxlen)
				maxlen = len;
		}
	}
	/* 2 = ::, 1=:, 1=eol */
	maxlen += strlen(pmu->name) + 2 + 1 + 1;
	buf = malloc(maxlen);
	if (!buf)
		return PFM_ERR_NOMEM;

	pfmlib_for_each_pmu_event(pmu, i) {
		ret = pmu->get_event_info(pmu, i, &einfo);
		if (ret != PFM_SUCCESS) {
			retval = ret;
			continue;
		}

		um = 0;
		for_each_pmu_event_attr(u, &einfo) {
			ret = pmu->get_event_attr_info(pmu, i, u, &ainfo);
			if (ret != PFM_SUCCESS) {
				retval = ret;
				continue;
			}

			if (ainfo.type != PFM_ATTR_UMASK)
				continue;

			/*
			 * XXX: some events may require more than one umasks to encode
			 */
			sprintf(buf, "%s::%s:%s", pmu->name, einfo.name, ainfo.name);
			ret = pfmlib_validate_encoding(buf, PFM_PLM3|PFM_PLM0);
			if (ret != PFM_SUCCESS) {
				if (pmu->can_auto_encode) {
					if (!pmu->can_auto_encode(pmu, i, u))
						continue;
				}
				/*
				 * some PMU may not support raw encoding
				 */
				if (ret != PFM_ERR_NOTSUPP) {
					fprintf(fp, "cannot encode event %s : %s\n", buf, pfm_strerror(ret));
					retval = ret;
				}
				continue;
			}
			um++;
		}
		if (um == 0) {
			sprintf(buf, "%s::%s", pmu->name, einfo.name);
			ret = pfmlib_validate_encoding(buf, PFM_PLM3|PFM_PLM0);
			if (ret != PFM_SUCCESS) {
				if (pmu->can_auto_encode) {
					if (!pmu->can_auto_encode(pmu, i, u))
						continue;
				}
				if (ret != PFM_ERR_NOTSUPP) {
					fprintf(fp, "cannot encode event %s : %s\n", buf, pfm_strerror(ret));
					retval = ret;
				}
				continue;
			}
		}
	}
	free(buf);

	return retval;
}

int
pfm_pmu_validate(pfm_pmu_t pmu_id, FILE *fp)
{
	pfmlib_pmu_t *pmu, *pmx;
	int nos = 0;
	int i, ret;

	if (fp == NULL)
		return PFM_ERR_INVAL;

	pmu = pmu2pmuidx(pmu_id);
	if (!pmu)
		return PFM_ERR_INVAL;


	if (!pfmlib_pmu_initialized(pmu)) {
		fprintf(fp, "pmu: %s :: initialization failed\n", pmu->name);
		return PFM_ERR_INVAL;
	}

	if (!pmu->name) {
		fprintf(fp, "pmu id: %d :: no name\n", pmu->pmu);
		return PFM_ERR_INVAL;
	}

	if (!pmu->desc) {
		fprintf(fp, "pmu: %s :: no description\n", pmu->name);
		return PFM_ERR_INVAL;
	}

	if (pmu->pmu >= PFM_PMU_MAX) {
		fprintf(fp, "pmu: %s :: invalid PMU id\n", pmu->name);
		return PFM_ERR_INVAL;
	}

	if (pmu->max_encoding >= PFMLIB_MAX_ENCODING) {
		fprintf(fp, "pmu: %s :: max encoding too high\n", pmu->name);
		return PFM_ERR_INVAL;
	}

	if (pfmlib_pmu_active(pmu)  && !pmu->pme_count) {
		fprintf(fp, "pmu: %s :: no events\n", pmu->name);
		return PFM_ERR_INVAL;
	}
	if (!pmu->pmu_detect) {
		fprintf(fp, "pmu: %s :: missing pmu_detect callback\n", pmu->name);
		return PFM_ERR_INVAL;
	}
	if (!pmu->get_event_first) {
		fprintf(fp, "pmu: %s :: missing get_event_first callback\n", pmu->name);
		return PFM_ERR_INVAL;
	}
	if (!pmu->get_event_next) {
		fprintf(fp, "pmu: %s :: missing get_event_next callback\n", pmu->name);
		return PFM_ERR_INVAL;
	}
	if (!pmu->get_event_info) {
		fprintf(fp, "pmu: %s :: missing get_event_info callback\n", pmu->name);
		return PFM_ERR_INVAL;
	}
	if (!pmu->get_event_attr_info) {
		fprintf(fp, "pmu: %s :: missing get_event_attr_info callback\n", pmu->name);
		return PFM_ERR_INVAL;
	}
	for (i = PFM_OS_NONE; i < PFM_OS_MAX; i++) {
		if (pmu->get_event_encoding[i])
			nos++;
	}
	if (!nos) {
		fprintf(fp, "pmu: %s :: no os event encoding callback\n", pmu->name);
		return PFM_ERR_INVAL;
	}
	if (!pmu->max_encoding) {
		fprintf(fp, "pmu: %s :: max_encoding is zero\n", pmu->name);
		return PFM_ERR_INVAL;
	}

	/* look for duplicate names, id */
	pfmlib_for_each_pmu(i) {
		pmx = pfmlib_pmus[i];
		if (!pfmlib_pmu_active(pmx))
			continue;
		if (pmx == pmu)
			continue;
		if (!strcasecmp(pmx->name, pmu->name)) {
			fprintf(fp, "pmu: %s :: duplicate name\n", pmu->name);
			return PFM_ERR_INVAL;
		}
		if (pmx->pmu == pmu->pmu) {
			fprintf(fp, "pmu: %s :: duplicate id\n", pmu->name);
			return PFM_ERR_INVAL;
		}
	}

	if (pmu->validate_table) {
		ret = pmu->validate_table(pmu, fp);
		if (ret != PFM_SUCCESS)
			return ret;
	}
	return pfmlib_pmu_validate_encoding(pmu, fp);
}

int
pfm_get_event_info(int idx, pfm_os_t os, pfm_event_info_t *uinfo)
{
	pfm_event_info_t info;
	pfmlib_event_desc_t e;
	pfmlib_pmu_t *pmu;
	size_t sz = sizeof(info);
	int pidx, ret;

	if (!PFMLIB_INITIALIZED())
		return PFM_ERR_NOINIT;

	if (os >= PFM_OS_MAX)
		return PFM_ERR_INVAL;

	pmu = pfmlib_idx2pidx(idx, &pidx);
	if (!pmu)
		return PFM_ERR_INVAL;

	if (!uinfo)
		return PFM_ERR_INVAL;

	sz = pfmlib_check_struct(uinfo, uinfo->size, PFM_EVENT_INFO_ABI0, sz);
	if (!sz)
		return PFM_ERR_INVAL;

	memset(&info, 0, sizeof(info));

	info.size = sz;

	/* default data type is uint64 */
	info.dtype = PFM_DTYPE_UINT64;

	/* initialize flags */
	info.is_speculative = PFM_EVENT_INFO_SPEC_NA;

	ret = pmu->get_event_info(pmu, pidx, &info);
	if (ret != PFM_SUCCESS)
		return ret;

	info.pmu = pmu->pmu;
	info.idx = idx;

	memset(&e, 0, sizeof(e));
	e.event = pidx;
	e.osid  = os;
	e.pmu   = pmu;

	ret = pfmlib_build_event_pattrs(&e);
	if (ret == PFM_SUCCESS) {
		info.nattrs = e.npattrs;
		memcpy(uinfo, &info, sz);
	}

	pfmlib_release_event(&e);
	return ret;
}

int
pfm_get_event_attr_info(int idx, int attr_idx, pfm_os_t os, pfm_event_attr_info_t *uinfo)
{
	pfmlib_event_attr_info_t *info;
	pfmlib_event_desc_t e;
	pfmlib_pmu_t *pmu;
	size_t sz = sizeof(*info);
	int pidx, ret;

	if (!PFMLIB_INITIALIZED())
		return PFM_ERR_NOINIT;

	if (attr_idx < 0)
		return PFM_ERR_INVAL;

	if (os >= PFM_OS_MAX)
		return PFM_ERR_INVAL;

	pmu = pfmlib_idx2pidx(idx, &pidx);
	if (!pmu)
		return PFM_ERR_INVAL;

	if (!uinfo)
		return PFM_ERR_INVAL;

	sz = pfmlib_check_struct(uinfo, uinfo->size, PFM_ATTR_INFO_ABI0, sz);
	if (!sz)
		return PFM_ERR_INVAL;

	memset(&e, 0, sizeof(e));
	e.event = pidx;
	e.osid  = os;
	e.pmu   = pmu;

	ret = pfmlib_build_event_pattrs(&e);
	if (ret != PFM_SUCCESS)
		return ret;

	ret = PFM_ERR_INVAL;

	if (attr_idx >= e.npattrs)
		goto error;

	info = &e.pattrs[attr_idx];

	/*
	 * info.idx = private, namespace specific index,
	 * should not be visible externally, so override
	 * with public index
	 *
	 * cannot memcpy() info into uinfo as they do not
	 * have the same size, cf. idx field (uint64 vs, uint32)
	 */
	uinfo->name  = info->name;
	uinfo->desc  = info->desc;
	uinfo->equiv = info->equiv;
	uinfo->size  = sz;
	uinfo->code  = info->code;
	uinfo->type  = info->type;
	uinfo->idx   = attr_idx;
	uinfo->ctrl  = info->ctrl;
	uinfo->is_dfl= info->is_dfl;
	uinfo->is_precise = info->is_precise;
	uinfo->is_speculative = info->is_speculative;
	uinfo->support_hw_smpl = info->support_hw_smpl;
	uinfo->reserved_bits = 0;
	uinfo->dfl_val64 = info->dfl_val64;

	ret = PFM_SUCCESS;
error:
	pfmlib_release_event(&e);
	return ret;
}

int
pfm_get_pmu_info(pfm_pmu_t pmuid, pfm_pmu_info_t *uinfo)
{
	pfm_pmu_info_t info;
	pfmlib_pmu_t *pmu;
	size_t sz = sizeof(info);
	int pidx;

	if (!PFMLIB_INITIALIZED())
		return PFM_ERR_NOINIT;

	if (pmuid >= PFM_PMU_MAX)
		return PFM_ERR_INVAL;

	if (!uinfo)
		return PFM_ERR_INVAL;

	sz = pfmlib_check_struct(uinfo, uinfo->size, PFM_PMU_INFO_ABI0, sz);
	if (!sz)
		return PFM_ERR_INVAL;
 
	pmu = pfmlib_pmus_map[pmuid];
	if (!pmu)
		return PFM_ERR_NOTSUPP;

	info.name = pmu->name;
	info.desc = pmu->desc;
	info.pmu  = pmuid;
	info.size = sz;

	info.max_encoding    = pmu->max_encoding;
	info.num_cntrs       = pmu->num_cntrs;
	info.num_fixed_cntrs = pmu->num_fixed_cntrs;

	pidx = pmu->get_event_first(pmu);
	if (pidx == -1)
		info.first_event = -1;
	else
		info.first_event = pfmlib_pidx2idx(pmu, pidx);

	/*
	 * XXX: pme_count only valid when PMU is detected
	 */
	info.is_present = pfmlib_pmu_active(pmu);
	info.is_dfl     = !!(pmu->flags & PFMLIB_PMU_FL_ARCH_DFL);
	info.type       = pmu->type;

	if (pmu->get_num_events)
		info.nevents = pmu->get_num_events(pmu);
	else
		info.nevents    = pmu->pme_count;

	memcpy(uinfo, &info, sz);

	return PFM_SUCCESS;
}

pfmlib_pmu_t *
pfmlib_get_pmu_by_type(pfm_pmu_type_t t)
{
	pfmlib_pmu_t *pmu;
	pfmlib_node_t *n;

	pfmlib_for_each_node(&pfmlib_active_pmus_list, n) {
		pmu = pfmlib_node_to_pmu(n);
		/* handle LIBPFM_ENCODE_INACTIVE=1 */
		if (!pfmlib_pmu_active(pmu))
			continue;
		/* first match */
		if (pmu->type != t)
			continue;

		return pmu;
	}
	return NULL;
}

static int
pfmlib_compare_attr_id(const void *a, const void *b)
{
	const pfmlib_attr_t *t1 = a;
	const pfmlib_attr_t *t2 = b;

	if (t1->id < t2->id)
		return -1;
	return t1->id == t2->id ? 0 : 1;
}

void
pfmlib_sort_attr(pfmlib_event_desc_t *e)
{
	qsort(e->attrs, e->nattrs, sizeof(pfmlib_attr_t), pfmlib_compare_attr_id);
}

static int
pfmlib_raw_pmu_encode(void *this, const char *str, int dfl_plm, void *data)
{
	pfm_pmu_encode_arg_t arg;
	pfm_pmu_encode_arg_t *uarg = data;

	pfmlib_pmu_t *pmu;
	pfmlib_event_desc_t e;
	size_t sz = sizeof(arg);
	int ret, i;

	sz = pfmlib_check_struct(uarg, uarg->size, PFM_RAW_ENCODE_ABI0, sz);
	if (!sz)
		return PFM_ERR_INVAL;

	memset(&arg, 0, sizeof(arg));

	/*
	 * get input data
	 */
	memcpy(&arg, uarg, sz);

	memset(&e, 0, sizeof(e));

	e.osid    = PFM_OS_NONE;
	e.dfl_plm = dfl_plm;

	ret = pfmlib_parse_event(str, &e);
	if (ret != PFM_SUCCESS)
		return ret;

	pmu = e.pmu;

	if (!pmu->get_event_encoding[PFM_OS_NONE]) {
		DPRINT("PMU %s does not support PFM_OS_NONE\n", pmu->name);
		ret = PFM_ERR_NOTSUPP;
		goto error;
	}

	ret = pmu->get_event_encoding[PFM_OS_NONE](pmu, &e);
	if (ret != PFM_SUCCESS)
		goto error;
	/*
	 * return opaque event identifier
	 */
	arg.idx = pfmlib_pidx2idx(e.pmu, e.event);

	if (arg.codes == NULL) {
		ret = PFM_ERR_NOMEM;
		arg.codes = malloc(sizeof(uint64_t) * e.count);
		if (!arg.codes)
			goto error_fstr;
	} else if (arg.count < e.count) {
		ret = PFM_ERR_TOOSMALL;
		goto error_fstr;
	}

	arg.count = e.count;

	for (i = 0; i < e.count; i++)
		arg.codes[i] = e.codes[i];

	if (arg.fstr) {
		ret = pfmlib_build_fstr(&e, arg.fstr);
		if (ret != PFM_SUCCESS)
			goto error;
	}

	ret = PFM_SUCCESS;

	/* copy out results */
	memcpy(uarg, &arg, sz);

error_fstr:
	if (ret != PFM_SUCCESS)
		free(arg.fstr);
error:
	/*
	 * release resources allocated for event
	 */
	pfmlib_release_event(&e);
	return ret;
}

static int
pfmlib_raw_pmu_detect(void *this)
{
	return PFM_SUCCESS;
}

static pfmlib_os_t pfmlib_os_none= {
	.name = "No OS (raw PMU)",
	.id = PFM_OS_NONE,
	.flags = PFMLIB_OS_FL_ACTIVATED,
	.encode = pfmlib_raw_pmu_encode,
	.detect = pfmlib_raw_pmu_detect,
};
