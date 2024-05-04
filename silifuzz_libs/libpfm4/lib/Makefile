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

#
# Common files
#
SRCS=pfmlib_common.c

ifeq ($(SYS),Linux)
CFLAGS += -DHAS_OPENAT
SRCS += pfmlib_perf_event_pmu.c pfmlib_perf_event.c pfmlib_perf_event_raw.c
endif

CFLAGS+=-D_REENTRANT -I. -fvisibility=hidden

#
# list all library support modules
#
ifeq ($(CONFIG_PFMLIB_ARCH_IA64),y)
INCARCH = $(INC_IA64)
#SRCS   += pfmlib_gen_ia64.c pfmlib_itanium.c pfmlib_itanium2.c pfmlib_montecito.c
CFLAGS += -DCONFIG_PFMLIB_ARCH_IA64
endif

ifeq ($(CONFIG_PFMLIB_ARCH_X86),y)

ifeq ($(SYS),Linux)
SRCS += pfmlib_intel_x86_perf_event.c pfmlib_amd64_perf_event.c \
	pfmlib_intel_netburst_perf_event.c \
	pfmlib_intel_snbep_unc_perf_event.c
endif

INCARCH = $(INC_X86)
SRCS   += pfmlib_amd64.c pfmlib_intel_core.c pfmlib_intel_x86.c \
	  pfmlib_intel_x86_arch.c pfmlib_intel_atom.c \
	  pfmlib_intel_nhm_unc.c pfmlib_intel_nhm.c \
	  pfmlib_intel_wsm.c  \
	  pfmlib_intel_snb.c pfmlib_intel_snb_unc.c \
	  pfmlib_intel_ivb.c pfmlib_intel_ivb_unc.c \
	  pfmlib_intel_hsw.c \
	  pfmlib_intel_bdw.c \
	  pfmlib_intel_skl.c \
	  pfmlib_intel_icl.c \
	  pfmlib_intel_spr.c \
	  pfmlib_intel_rapl.c \
	  pfmlib_intel_snbep_unc.c \
	  pfmlib_intel_snbep_unc_cbo.c \
	  pfmlib_intel_snbep_unc_ha.c \
	  pfmlib_intel_snbep_unc_imc.c \
	  pfmlib_intel_snbep_unc_pcu.c \
	  pfmlib_intel_snbep_unc_qpi.c \
	  pfmlib_intel_snbep_unc_ubo.c \
	  pfmlib_intel_snbep_unc_r2pcie.c \
	  pfmlib_intel_snbep_unc_r3qpi.c \
	  pfmlib_intel_ivbep_unc_cbo.c \
	  pfmlib_intel_ivbep_unc_ha.c \
	  pfmlib_intel_ivbep_unc_imc.c \
	  pfmlib_intel_ivbep_unc_pcu.c \
	  pfmlib_intel_ivbep_unc_qpi.c \
	  pfmlib_intel_ivbep_unc_ubo.c \
	  pfmlib_intel_ivbep_unc_r2pcie.c \
	  pfmlib_intel_ivbep_unc_r3qpi.c \
	  pfmlib_intel_ivbep_unc_irp.c \
	  pfmlib_intel_hswep_unc_cbo.c \
	  pfmlib_intel_hswep_unc_ha.c \
	  pfmlib_intel_hswep_unc_imc.c \
	  pfmlib_intel_hswep_unc_pcu.c \
	  pfmlib_intel_hswep_unc_qpi.c \
	  pfmlib_intel_hswep_unc_ubo.c \
	  pfmlib_intel_hswep_unc_r2pcie.c \
	  pfmlib_intel_hswep_unc_r3qpi.c \
	  pfmlib_intel_hswep_unc_irp.c \
	  pfmlib_intel_hswep_unc_sbo.c \
	  pfmlib_intel_bdx_unc_cbo.c \
	  pfmlib_intel_bdx_unc_ubo.c \
	  pfmlib_intel_bdx_unc_sbo.c \
	  pfmlib_intel_bdx_unc_ha.c \
	  pfmlib_intel_bdx_unc_imc.c \
	  pfmlib_intel_bdx_unc_irp.c \
	  pfmlib_intel_bdx_unc_pcu.c \
	  pfmlib_intel_bdx_unc_qpi.c \
	  pfmlib_intel_bdx_unc_r2pcie.c \
	  pfmlib_intel_bdx_unc_r3qpi.c \
	  pfmlib_intel_skx_unc_cha.c \
	  pfmlib_intel_skx_unc_iio.c \
	  pfmlib_intel_skx_unc_imc.c \
	  pfmlib_intel_skx_unc_irp.c \
	  pfmlib_intel_skx_unc_m2m.c \
	  pfmlib_intel_skx_unc_m3upi.c \
	  pfmlib_intel_skx_unc_pcu.c \
	  pfmlib_intel_skx_unc_ubo.c \
	  pfmlib_intel_skx_unc_upi.c \
	  pfmlib_intel_icx_unc_cha.c \
	  pfmlib_intel_icx_unc_imc.c \
	  pfmlib_intel_icx_unc_m2m.c \
	  pfmlib_intel_icx_unc_iio.c \
	  pfmlib_intel_icx_unc_irp.c \
	  pfmlib_intel_icx_unc_pcu.c \
	  pfmlib_intel_icx_unc_upi.c \
	  pfmlib_intel_icx_unc_m3upi.c \
	  pfmlib_intel_icx_unc_ubox.c \
	  pfmlib_intel_icx_unc_m2pcie.c \
	  pfmlib_intel_spr_unc_imc.c \
	  pfmlib_intel_spr_unc_upi.c \
	  pfmlib_intel_spr_unc_cha.c \
	  pfmlib_intel_knc.c \
	  pfmlib_intel_slm.c \
	  pfmlib_intel_tmt.c \
	  pfmlib_intel_knl.c \
	  pfmlib_intel_adl.c \
	  pfmlib_intel_knl_unc_imc.c \
	  pfmlib_intel_knl_unc_edc.c \
	  pfmlib_intel_knl_unc_cha.c \
	  pfmlib_intel_knl_unc_m2pcie.c \
	  pfmlib_intel_glm.c \
	  pfmlib_intel_netburst.c \
	  pfmlib_amd64_k7.c pfmlib_amd64_k8.c pfmlib_amd64_fam10h.c \
	  pfmlib_amd64_fam11h.c pfmlib_amd64_fam12h.c \
	  pfmlib_amd64_fam14h.c pfmlib_amd64_fam15h.c \
	  pfmlib_amd64_fam17h.c pfmlib_amd64_fam16h.c \
	  pfmlib_amd64_fam19h.c pfmlib_amd64_rapl.c \
	  pfmlib_amd64_fam19h_l3.c

CFLAGS += -DCONFIG_PFMLIB_ARCH_X86

ifeq ($(CONFIG_PFMLIB_ARCH_I386),y)
SRCS += pfmlib_intel_coreduo.c pfmlib_intel_p6.c
CFLAGS += -DCONFIG_PFMLIB_ARCH_I386
endif

ifeq ($(CONFIG_PFMLIB_ARCH_X86_64),y)
CFLAGS += -DCONFIG_PFMLIB_ARCH_X86_64
endif

endif

ifeq ($(CONFIG_PFMLIB_ARCH_POWERPC),y)

ifeq ($(SYS),Linux)
SRCS += pfmlib_powerpc_perf_event.c
endif

INCARCH = $(INC_POWERPC)
SRCS   += pfmlib_powerpc.c pfmlib_power4.c pfmlib_ppc970.c pfmlib_power5.c \
	pfmlib_power6.c pfmlib_power7.c pfmlib_torrent.c pfmlib_power8.c \
	pfmlib_power9.c pfmlib_powerpc_nest.c pfmlib_power10.c
CFLAGS += -DCONFIG_PFMLIB_ARCH_POWERPC
endif

ifeq ($(CONFIG_PFMLIB_ARCH_S390X),y)

ifeq ($(SYS),Linux)
SRCS += pfmlib_s390x_perf_event.c
endif

INCARCH = $(INC_S390X)
SRCS   += pfmlib_s390x_cpumf.c
CFLAGS += -DCONFIG_PFMLIB_ARCH_S390X
endif

ifeq ($(CONFIG_PFMLIB_ARCH_SPARC),y)

ifeq ($(SYS),Linux)
SRCS += pfmlib_sparc_perf_event.c
endif

INCARCH = $(INC_SPARC)
SRCS   += pfmlib_sparc.c pfmlib_sparc_ultra12.c pfmlib_sparc_ultra3.c pfmlib_sparc_ultra4.c pfmlib_sparc_niagara.c
CFLAGS += -DCONFIG_PFMLIB_ARCH_SPARC
endif

ifeq ($(CONFIG_PFMLIB_ARCH_ARM),y)

ifeq ($(SYS),Linux)
SRCS += pfmlib_arm_perf_event.c
endif

INCARCH = $(INC_ARM)
SRCS   += pfmlib_arm.c pfmlib_arm_armv7_pmuv1.c pfmlib_arm_armv6.c pfmlib_arm_armv8.c pfmlib_arm_armv9.c pfmlib_tx2_unc_perf_event.c pfmlib_kunpeng_unc_perf_event.c
CFLAGS += -DCONFIG_PFMLIB_ARCH_ARM
endif

ifeq ($(CONFIG_PFMLIB_ARCH_ARM64),y)

ifeq ($(SYS),Linux)
SRCS += pfmlib_arm_perf_event.c
endif

INCARCH = $(INC_ARM64)
SRCS   += pfmlib_arm.c pfmlib_arm_armv8.c pfmlib_arm_armv9.c pfmlib_tx2_unc_perf_event.c pfmlib_kunpeng_unc_perf_event.c
CFLAGS += -DCONFIG_PFMLIB_ARCH_ARM64
endif

ifeq ($(CONFIG_PFMLIB_ARCH_MIPS),y)

ifeq ($(SYS),Linux)
SRCS += pfmlib_mips_perf_event.c
endif

INCARCH = $(INC_MIPS)
SRCS   += pfmlib_mips.c pfmlib_mips_74k.c
CFLAGS += -DCONFIG_PFMLIB_ARCH_MIPS
endif

ifeq ($(CONFIG_PFMLIB_CELL),y)
INCARCH = $(INC_CELL)
#SRCS   += pfmlib_cell.c
CFLAGS += -DCONFIG_PFMLIB_CELL
endif

ifeq ($(SYS),Linux)
SLDFLAGS=$(LDFLAGS) -shared -Wl,-soname -Wl,$(VLIBPFM)
SLIBPFM=libpfm.so.$(VERSION).$(REVISION).$(AGE)
VLIBPFM=libpfm.so.$(VERSION)
SOLIBEXT=so
endif

CFLAGS+=-I.
ALIBPFM=libpfm.a

TARGETS=$(ALIBPFM)

ifeq ($(CONFIG_PFMLIB_SHARED),y)
TARGETS += $(SLIBPFM)
endif

OBJS=$(SRCS:.c=.o)
SOBJS=$(OBJS:.o=.lo)

INC_COMMON= $(PFMINCDIR)/perfmon/pfmlib.h pfmlib_priv.h

ifeq ($(SYS),Linux)
INC_COMMON += $(PFMINCDIR)/perfmon/perf_event.h events/perf_events.h
endif

INC_IA64=pfmlib_ia64_priv.h	 \
	events/itanium_events.h	 \
	events/itanium2_events.h \
	events/montecito_events.h

INC_X86= pfmlib_intel_x86_priv.h	\
	pfmlib_amd64_priv.h		\
	events/amd64_events_k7.h    	\
	events/amd64_events_k8.h    	\
	events/amd64_events_fam10h.h	\
	events/amd64_events_fam11h.h	\
	events/amd64_events_fam12h.h	\
	events/amd64_events_fam14h.h	\
	events/amd64_events_fam15h.h	\
	events/amd64_events_fam17h_zen1.h \
	events/amd64_events_fam17h_zen2.h \
	events/amd64_events_fam19h_zen3.h \
	events/amd64_events_fam19h_zen4.h \
	events/amd64_events_fam19h_zen3_l3.h \
	events/amd64_events_fam16h.h	\
	events/intel_p6_events.h	\
	events/intel_netburst_events.h	\
	events//intel_x86_arch_events.h \
	events/intel_coreduo_events.h	\
	events/intel_core_events.h	\
	events/intel_atom_events.h	\
	events/intel_nhm_events.h	\
	events/intel_nhm_unc_events.h	\
	events/intel_wsm_events.h	\
	events/intel_wsm_unc_events.h	\
	events/intel_snb_events.h	\
	events/intel_snb_unc_events.h	\
	events/intel_ivb_events.h	\
	events/intel_hsw_events.h	\
	events/intel_bdw_events.h	\
	events/intel_skl_events.h	\
	events/intel_glm_events.h	\
	events/intel_icl_events.h	\
	events/intel_spr_events.h	\
	events/intel_adl_glc_events.h	\
	events/intel_adl_grt_events.h	\
	pfmlib_intel_snbep_unc_priv.h	\
	events/intel_snbep_unc_cbo_events.h \
	events/intel_snbep_unc_ha_events.h \
	events/intel_snbep_unc_imc_events.h \
	events/intel_snbep_unc_pcu_events.h \
	events/intel_snbep_unc_qpi_events.h \
	events/intel_snbep_unc_ubo_events.h \
	events/intel_snbep_unc_r2pcie_events.h \
	events/intel_snbep_unc_r3qpi_events.h \
	events/intel_tmt_events.h \
	events/intel_knc_events.h \
	events/intel_knl_events.h \
	events/intel_ivbep_unc_cbo_events.h \
	events/intel_ivbep_unc_ha_events.h \
	events/intel_ivbep_unc_imc_events.h \
	events/intel_ivbep_unc_pcu_events.h \
	events/intel_ivbep_unc_qpi_events.h \
	events/intel_ivbep_unc_ubo_events.h \
	events/intel_ivbep_unc_r2pcie_events.h \
	events/intel_ivbep_unc_r3qpi_events.h \
	events/intel_ivbep_unc_irp_events.h \
	events/intel_hswep_unc_cbo_events.h \
	events/intel_hswep_unc_sbo_events.h \
	events/intel_hswep_unc_ha_events.h \
	events/intel_hswep_unc_imc_events.h \
	events/intel_hswep_unc_pcu_events.h \
	events/intel_hswep_unc_qpi_events.h \
	events/intel_hswep_unc_ubo_events.h \
	events/intel_hswep_unc_r2pcie_events.h \
	events/intel_hswep_unc_r3qpi_events.h \
	events/intel_hswep_unc_irp_events.h \
	events/intel_bdx_unc_cbo_events.h \
	events/intel_bdx_unc_ubo_events.h \
	events/intel_bdx_unc_sbo_events.h \
	events/intel_bdx_unc_ha_events.h \
	events/intel_bdx_unc_imc_events.h \
	events/intel_bdx_unc_irp_events.h \
	events/intel_bdx_unc_pcu_events.h \
	events/intel_bdx_unc_qpi_events.h \
	events/intel_bdx_unc_r2pcie_events.h \
	events/intel_bdx_unc_r3qpi_events.h \
	events/intel_skx_unc_cha_events.h \
	events/intel_skx_unc_iio_events.h \
	events/intel_skx_unc_imc_events.h \
	events/intel_skx_unc_irp_events.h \
	events/intel_skx_unc_m2m_events.h \
	events/intel_skx_unc_m3upi_events.h \
	events/intel_skx_unc_pcu_events.h \
	events/intel_skx_unc_ubo_events.h \
	events/intel_skx_unc_upi_events.h \
	events/intel_knl_unc_imc_events.h \
	events/intel_knl_unc_edc_events.h \
	events/intel_knl_unc_cha_events.h \
	events/intel_knl_unc_m2pcie_events.h \
	events/intel_icx_unc_cha_events.h \
	events/intel_icx_unc_imc_events.h \
	events/intel_icx_unc_m2m_events.h \
	events/intel_icx_unc_irp_events.h \
	events/intel_icx_unc_pcu_events.h \
	events/intel_icx_unc_upi_events.h \
	events/intel_icx_unc_m3upi_events.h \
	events/intel_icx_unc_ubox_events.h \
	events/intel_icx_unc_m2pcie_events.h \
	events/intel_spr_unc_imc_events.h \
	events/intel_spr_unc_upi_events.h \
	events/intel_spr_unc_cha_events.h \
	events/intel_slm_events.h

INC_MIPS=events/mips_74k_events.h events/mips_74k_events.h

INC_POWERPC=events/ppc970_events.h	\
	events/ppc970mp_events.h	\
	events/power4_events.h		\
	events/power5_events.h		\
	events/power5+_events.h		\
	events/power6_events.h		\
	events/power7_events.h		\
	events/power8_events.h		\
	events/power9_events.h		\
	events/power10_events.h		\
	events/torrent_events.h		\
	events/powerpc_nest_events.h

INC_S390X=pfmlib_s390x_priv.h \
	events/s390x_cpumf_events.h

INC_SPARC=events/sparc_ultra12_events.h		\
	events/sparc_ultra3_events.h		\
	events/sparc_ultra3plus_events.h	\
	events/sparc_ultra3i_events.h		\
	events/sparc_ultra4plus_events.h	\
	events/sparc_niagara1_events.h		\
	events/sparc_niagara2_events.h

INC_CELL=events/cell_events.h

INC_ARM=pfmlib_arm_priv.h			\
	events/arm_cortex_a7_events.h		\
	events/arm_cortex_a8_events.h		\
	events/arm_cortex_a9_events.h		\
	events/arm_cortex_a15_events.h		\
	events/arm_cortex_a57_events.h		\
	events/arm_cortex_a53_events.h		\
        events/arm_xgene_events.h		\
	events/arm_cavium_tx2_events.h		\
	events/arm_marvell_tx2_unc_events.h	\
	events/arm_neoverse_n1_events.h		\
	events/arm_neoverse_n2_events.h		\
	events/arm_neoverse_v1_events.h		\
	events/arm_neoverse_v2_events.h		\
	events/arm_hisilicon_kunpeng_events.h \
	events/arm_hisilicon_kunpeng_unc_events.h

INC_ARM64=pfmlib_arm_priv.h			\
	events/arm_cortex_a57_events.h		\
	events/arm_cortex_a53_events.h		\
        events/arm_xgene_events.h		\
	events/arm_cavium_tx2_events.h		\
	events/arm_marvell_tx2_unc_events.h	\
	events/arm_fujitsu_a64fx_events.h	\
	events/arm_neoverse_n1_events.h		\
	events/arm_neoverse_n2_events.h		\
	events/arm_neoverse_v1_events.h		\
	events/arm_neoverse_v2_events.h		\
	events/arm_hisilicon_kunpeng_events.h \
	events/arm_hisilicon_kunpeng_unc_events.h

INCDEP=$(INC_COMMON) $(INCARCH)

all: $(TARGETS)

$(OBJS) $(SOBJS): $(TOPDIR)/config.mk $(TOPDIR)/rules.mk Makefile $(INCDEP)

libpfm.a:  $(OBJS)
	$(RM) $@
	$(AR) cq $@ $(OBJS)

$(SLIBPFM):  $(SOBJS)
	$(CC) $(CFLAGS) $(SLDFLAGS)  -o $@ $(SOBJS)
	$(LN) $@ $(VLIBPFM)
	$(LN) $@ libpfm.$(SOLIBEXT)

clean:
	$(RM) -f *.o *.lo *.a *.so* *~ *.$(SOLIBEXT)

distclean: clean

depend:
	$(MKDEP) $(CFLAGS) $(SRCS)

install: $(TARGETS)

install:
	@echo building: $(TARGETS)
	-mkdir -p $(DESTDIR)$(LIBDIR)
	$(INSTALL) -m 644 $(ALIBPFM) $(DESTDIR)$(LIBDIR)
ifeq ($(CONFIG_PFMLIB_SHARED),y)
	$(INSTALL) $(SLIBPFM) $(DESTDIR)$(LIBDIR)
	cd $(DESTDIR)$(LIBDIR); $(LN) $(SLIBPFM) $(VLIBPFM)
	cd $(DESTDIR)$(LIBDIR); $(LN) $(SLIBPFM) libpfm.$(SOLIBEXT)
	-$(LDCONFIG)
endif

tags:
	$(CTAGS) -o $(TOPDIR)/tags --tag-relative=yes $(SRCS) $(INCDEP)
