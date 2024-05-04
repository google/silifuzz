#
# Copyright (c) 2002-2006 Hewlett-Packard Development Company, L.P.
# Contributed by Stephane Eranian <eranian@hpl.hp.com>
#
# Copyright (c) 2022, NVIDIA CORPORATION & AFFILIATES.
# Contributed by John Linford <jlinford@nvidia.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy 
# of this software and associated documentation files (the "Software"), to deal 
# in the Software without restriction, including without limitation the rights 
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies 
# of the Software, and to permit persons to whom the Software is furnished to do so, 
# subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all 
# copies or substantial portions of the Software.  
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF 
# CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE 
# OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

TOPDIR  := $(shell if [ "$$PWD" != "" ]; then echo $$PWD; else pwd; fi)/..

include $(TOPDIR)/config.mk
include $(TOPDIR)/rules.mk

.PHONY: all clean distclean depend

ARCH_MAN=
SYS_MAN=

ifeq ($(CONFIG_PFMLIB_ARCH_X86),y)
ARCH_MAN=libpfm_intel_core.3	\
	 libpfm_intel_x86_arch.3\
	 libpfm_amd64.3		\
	 libpfm_amd64_k7.3	\
	 libpfm_amd64_k8.3	\
	 libpfm_amd64_fam10h.3	\
	 libpfm_amd64_fam15h.3	\
	 libpfm_amd64_fam16h.3	\
	 libpfm_amd64_fam17h.3	\
	 libpfm_amd64_fam17h_zen2.3 \
	 libpfm_amd64_fam19h_zen3.3 \
	 libpfm_amd64_fam19h_zen4.3 \
	 libpfm_amd64_fam19h_zen3_l3.3 \
	 libpfm_intel_atom.3	\
	 libpfm_intel_nhm.3	\
	 libpfm_intel_nhm_unc.3 \
	 libpfm_intel_wsm.3	\
	 libpfm_intel_wsm_unc.3 \
	 libpfm_intel_snb.3	\
	 libpfm_intel_snb_unc.3 \
	 libpfm_intel_ivb.3	\
	 libpfm_intel_ivb_unc.3 \
	 libpfm_intel_hsw.3	\
	 libpfm_intel_bdw.3	\
	 libpfm_intel_rapl.3	\
	 libpfm_intel_slm.3	\
	 libpfm_intel_tmt.3	\
	 libpfm_intel_skl.3	\
	 libpfm_intel_icl.3	\
	 libpfm_intel_icx.3	\
	 libpfm_intel_spr.3	\
	 libpfm_intel_emr.3	\
	 libpfm_intel_glm.3	\
	 libpfm_intel_adl_glc.3	\
	 libpfm_intel_adl_grt.3	\
	 libpfm_intel_knl.3	\
	 libpfm_intel_knm.3	\
	 libpfm_intel_snbep_unc_cbo.3 \
	 libpfm_intel_snbep_unc_ha.3 \
	 libpfm_intel_snbep_unc_imc.3 \
	 libpfm_intel_snbep_unc_pcu.3 \
	 libpfm_intel_snbep_unc_qpi.3 \
	 libpfm_intel_snbep_unc_ubo.3 \
	 libpfm_intel_snbep_unc_r2pcie.3 \
	 libpfm_intel_snbep_unc_r3qpi.3 \
	 libpfm_intel_ivbep_unc_cbo.3 \
	 libpfm_intel_ivbep_unc_ha.3 \
	 libpfm_intel_ivbep_unc_imc.3 \
	 libpfm_intel_ivbep_unc_pcu.3 \
	 libpfm_intel_ivbep_unc_qpi.3 \
	 libpfm_intel_ivbep_unc_ubo.3 \
	 libpfm_intel_ivbep_unc_r2pcie.3 \
	 libpfm_intel_ivbep_unc_r3qpi.3 \
	 libpfm_intel_ivbep_unc_irp.3 \
	 libpfm_intel_knc.3 \
	 libpfm_intel_hswep_unc_cbo.3 \
	 libpfm_intel_hswep_unc_ha.3 \
	 libpfm_intel_hswep_unc_imc.3 \
	 libpfm_intel_hswep_unc_irp.3 \
	 libpfm_intel_hswep_unc_pcu.3 \
	 libpfm_intel_hswep_unc_qpi.3 \
	 libpfm_intel_hswep_unc_r2pcie.3 \
	 libpfm_intel_hswep_unc_r3qpi.3 \
	 libpfm_intel_hswep_unc_sbo.3 \
	 libpfm_intel_hswep_unc_ubo.3  \
	 libpfm_intel_bdx_unc_cbo.3 \
	 libpfm_intel_bdx_unc_ha.3 \
	 libpfm_intel_bdx_unc_imc.3 \
	 libpfm_intel_bdx_unc_irp.3 \
	 libpfm_intel_bdx_unc_pcu.3 \
	 libpfm_intel_bdx_unc_qpi.3 \
	 libpfm_intel_bdx_unc_r2pcie.3 \
	 libpfm_intel_bdx_unc_r3qpi.3 \
	 libpfm_intel_bdx_unc_sbo.3 \
	 libpfm_intel_bdx_unc_ubo.3 \
	 libpfm_intel_skx_unc_cha.3 \
	 libpfm_intel_skx_unc_imc.3 \
	 libpfm_intel_skx_unc_irp.3 \
	 libpfm_intel_skx_unc_m2m.3 \
	 libpfm_intel_skx_unc_m3upi.3 \
	 libpfm_intel_skx_unc_pcu.3 \
	 libpfm_intel_skx_unc_ubo.3 \
	 libpfm_intel_skx_unc_upi.3 \
	 libpfm_intel_icx_unc_cha.3 \
	 libpfm_intel_icx_unc_imc.3 \
	 libpfm_intel_icx_unc_m2m.3 \
	 libpfm_intel_icx_unc_iio.3 \
	 libpfm_intel_icx_unc_pcu.3 \
	 libpfm_intel_icx_unc_upi.3 \
	 libpfm_intel_icx_unc_m3upi.3 \
	 libpfm_intel_icx_unc_ubox.3 \
	 libpfm_intel_icx_unc_m2pcie.3 \
	 libpfm_intel_icx_unc_irp.3 \
	 libpfm_intel_spr_unc_imc.3 \
	 libpfm_intel_spr_unc_upi.3 \
	 libpfm_intel_spr_unc_cha.3


ifeq ($(CONFIG_PFMLIB_ARCH_I386),y)
ARCH_MAN += libpfm_intel_p6.3 libpfm_intel_coreduo.3
endif

endif

ifeq ($(CONFIG_PFMLIB_ARCH_ARM),y)
ARCH_MAN += libpfm_arm_xgene.3 \
	    libpfm_arm_ac7.3 \
	    libpfm_arm_ac57.3 \
	    libpfm_arm_ac53.3 \
	    libpfm_arm_ac15.3 \
	    libpfm_arm_ac8.3 \
	    libpfm_arm_ac9.3 \
	    libpfm_arm_qcom_krait.3 \
	    libpfm_arm_neoverse_n1.3 \
	    libpfm_arm_neoverse_n2.3 \
		libpfm_arm_neoverse_v1.3 \
		libpfm_arm_neoverse_v2.3
endif

ifeq ($(CONFIG_PFMLIB_ARCH_ARM64),y)
ARCH_MAN += libpfm_arm_xgene.3 \
	    libpfm_arm_ac57.3 \
	    libpfm_arm_ac53.3 \
	    libpfm_arm_a64fx.3 \
		libpfm_arm_neoverse_n1.3 \
	    libpfm_arm_neoverse_n2.3 \
		libpfm_arm_neoverse_v1.3 \
		libpfm_arm_neoverse_v2.3
endif

ifeq ($(CONFIG_PFMLIB_ARCH_MIPS),y)
ARCH_MAN += libpfm_mips_74k.3
endif

GEN_MAN= libpfm.3 \
	pfm_find_event.3 \
	pfm_get_event_attr_info.3 \
	pfm_get_event_info.3 \
	pfm_get_event_encoding.3 \
	pfm_get_event_next.3 \
	pfm_get_pmu_info.3 \
	pfm_get_os_event_encoding.3 \
	pfm_get_version.3 \
	pfm_initialize.3 \
	pfm_terminate.3 \
	pfm_strerror.3

ifeq ($(SYS),Linux)
SYS_MAN=pfm_get_perf_event_encoding.3 libpfm_perf_event_raw.3
endif

MAN=$(GEN_MAN) $(ARCH_MAN) $(SYS_MAN)

install:

	-mkdir -p $(DESTDIR)$(MANDIR)/man3
	( cd man3; $(INSTALL) -m 644 $(MAN) $(DESTDIR)$(MANDIR)/man3 )
