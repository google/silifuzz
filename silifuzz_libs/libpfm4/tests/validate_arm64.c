/*
 * validate_arm64.c - validate ARM64 event tables + encodings
 *
 * Copyright (c) 2014 Google, Inc
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
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <perfmon/pfmlib.h>

#define MAX_ENCODING	1
#define SRC_LINE	.line = __LINE__

typedef struct {
	const char *name;
	const char *fstr;
	uint64_t codes[MAX_ENCODING];
	int ret, count, line;
} test_event_t;

static const test_event_t arm64_test_events[]={
	{ SRC_LINE,
	  .name = "arm_ac57::CPU_CYCLES",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x8000011,
	  .fstr = "arm_ac57::CPU_CYCLES:k=1:u=1:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_ac57::CPU_CYCLES:k",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x88000011,
	  .fstr = "arm_ac57::CPU_CYCLES:k=1:u=0:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_ac57::CPU_CYCLES:k:u",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x8000011,
	  .fstr = "arm_ac57::CPU_CYCLES:k=1:u=1:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_ac57::INST_RETIRED",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x8000008,
	  .fstr = "arm_ac57::INST_RETIRED:k=1:u=1:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_ac53::CPU_CYCLES",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x8000011,
	  .fstr = "arm_ac53::CPU_CYCLES:k=1:u=1:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_ac53::CPU_CYCLES:k",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x88000011,
	  .fstr = "arm_ac53::CPU_CYCLES:k=1:u=0:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_ac53::CPU_CYCLES:k:u",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x8000011,
	  .fstr = "arm_ac53::CPU_CYCLES:k=1:u=1:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_ac53::INST_RETIRED",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x8000008,
	  .fstr = "arm_ac53::INST_RETIRED:k=1:u=1:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_ac53::LD_RETIRED",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x8000006,
	  .fstr = "arm_ac53::LD_RETIRED:k=1:u=1:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_ac53::ST_RETIRED",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x8000007,
	  .fstr = "arm_ac53::ST_RETIRED:k=1:u=1:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_xgene::CPU_CYCLES",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x8000011,
	  .fstr = "arm_xgene::CPU_CYCLES:k=1:u=1:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_xgene::CPU_CYCLES:k",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x88000011,
	  .fstr = "arm_xgene::CPU_CYCLES:k=1:u=0:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_xgene::CPU_CYCLES:k:u",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x8000011,
	  .fstr = "arm_xgene::CPU_CYCLES:k=1:u=1:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_xgene::INST_RETIRED",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x8000008,
	  .fstr = "arm_xgene::INST_RETIRED:k=1:u=1:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_thunderx2::CPU_CYCLES",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x8000011,
	  .fstr = "arm_thunderx2::CPU_CYCLES:k=1:u=1:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_thunderx2::CPU_CYCLES:k",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x88000011,
	  .fstr = "arm_thunderx2::CPU_CYCLES:k=1:u=0:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_thunderx2::LD_RETIRED",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x8000006,
	  .fstr = "arm_thunderx2::LD_RETIRED:k=1:u=1:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_thunderx2::ST_RETIRED",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x8000007,
	  .fstr = "arm_thunderx2::ST_RETIRED:k=1:u=1:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_thunderx2::INST_RETIRED",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x8000008,
	  .fstr = "arm_thunderx2::INST_RETIRED:k=1:u=1:hv=0",
	},
	{ SRC_LINE,
	  .name = "tx2_dmc1::UNC_DMC_READS",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0xf,
	  .fstr = "tx2_dmc1::UNC_DMC_READS",
	},
	{ SRC_LINE,
	  .name = "tx2_ccpi0::UNC_CCPI_GIC",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x12d,
	  .fstr = "tx2_ccpi0::UNC_CCPI_GIC",
	},
	{ SRC_LINE,
	  .name = "tx2_llc0::UNC_LLC_READ",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0xd,
	  .fstr = "tx2_llc0::UNC_LLC_READ",
	},
	{ SRC_LINE,
	  .name = "arm_a64fx::CPU_CYCLES",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x8000011,
	  .fstr = "arm_a64fx::CPU_CYCLES:k=1:u=1:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_a64fx::CPU_CYCLES:k",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x88000011,
	  .fstr = "arm_a64fx::CPU_CYCLES:k=1:u=0:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_a64fx::INST_RETIRED",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x8000008,
	  .fstr = "arm_a64fx::INST_RETIRED:k=1:u=1:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_n1::INST_RETIRED",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x8000008,
	  .fstr = "arm_n1::INST_RETIRED:k=1:u=1:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_n1::INST_RETIRED:k",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x88000008,
	  .fstr = "arm_n1::INST_RETIRED:k=1:u=0:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_n1::INST_RETIRED:u",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x48000008,
	  .fstr = "arm_n1::INST_RETIRED:k=0:u=1:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_n1::CPU_CYCLES",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x8000011,
	  .fstr = "arm_n1::CPU_CYCLES:k=1:u=1:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_n1::L3_CACHE_RD",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x80000a0,
	  .fstr = "arm_n1::L3_CACHE_RD:k=1:u=1:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_n1::BR_RET_SPEC",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x8000079,
	  .fstr = "arm_n1::BR_RETURN_SPEC:k=1:u=1:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_n2::CPU_CYCLES",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x8000011,
	  .fstr = "arm_n2::CPU_CYCLES:k=1:u=1:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_n2::CPU_CYCLES:u",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x48000011,
	  .fstr = "arm_n2::CPU_CYCLES:k=0:u=1:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_n2::CPU_CYCLES:k",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x88000011,
	  .fstr = "arm_n2::CPU_CYCLES:k=1:u=0:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_n2::LDST_ALIGN_LAT:k",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x88004020,
	  .fstr = "arm_n2::LDST_ALIGN_LAT:k=1:u=0:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_v1::INST_RETIRED",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x8000008,
	  .fstr = "arm_v1::INST_RETIRED:k=1:u=1:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_v1::INST_RETIRED:k",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x88000008,
	  .fstr = "arm_v1::INST_RETIRED:k=1:u=0:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_v1::INST_RETIRED:u",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x48000008,
	  .fstr = "arm_v1::INST_RETIRED:k=0:u=1:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_v1::CPU_CYCLES",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x8000011,
	  .fstr = "arm_v1::CPU_CYCLES:k=1:u=1:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_v1::BR_RET_SPEC",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x8000079,
	  .fstr = "arm_v1::BR_RETURN_SPEC:k=1:u=1:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_v2::INST_RETIRED",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x8000008,
	  .fstr = "arm_v2::INST_RETIRED:k=1:u=1:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_v2::INST_RETIRED:k",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x88000008,
	  .fstr = "arm_v2::INST_RETIRED:k=1:u=0:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_v2::INST_RETIRED:u",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x48000008,
	  .fstr = "arm_v2::INST_RETIRED:k=0:u=1:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_v2::CPU_CYCLES",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x8000011,
	  .fstr = "arm_v2::CPU_CYCLES:k=1:u=1:hv=0",
	},
	{ SRC_LINE,
	  .name = "arm_v2::BR_RET_SPEC",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x8000079,
	  .fstr = "arm_v2::BR_RETURN_SPEC:k=1:u=1:hv=0",
	},
	{ SRC_LINE,
		.name = "arm_kunpeng::CPU_CYCLES",
		.ret  = PFM_SUCCESS,
		.count = 1,
		.codes[0] = 0x8000011,
		.fstr = "arm_kunpeng::CPU_CYCLES:k=1:u=1:hv=0",
	},
	{ SRC_LINE,
		.name = "arm_kunpeng::CPU_CYCLES:k",
		.ret  = PFM_SUCCESS,
		.count = 1,
		.codes[0] = 0x88000011,
		.fstr = "arm_kunpeng::CPU_CYCLES:k=1:u=0:hv=0",
	},
	{ SRC_LINE,
		.name = "arm_kunpeng::INST_RETIRED",
		.ret  = PFM_SUCCESS,
		.count = 1,
		.codes[0] = 0x8000008,
		.fstr = "arm_kunpeng::INST_RETIRED:k=1:u=1:hv=0",
	},
	{ SRC_LINE,
	  .name = "hisi_sccl1_l3c8::rd_cpipe",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x00,
	  .fstr = "hisi_sccl1_l3c8::rd_cpipe",
	},
	{ SRC_LINE,
	  .name = "hisi_sccl1_hha2::rx_ops_num",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x00,
	  .fstr = "hisi_sccl1_hha2::rx_ops_num",
	},
	{ SRC_LINE,
	  .name = "hisi_sccl1_ddrc0::flux_wr",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x00,
	  .fstr = "hisi_sccl1_ddrc0::flux_wr",
	}
};
#define NUM_TEST_EVENTS (int)(sizeof(arm64_test_events)/sizeof(test_event_t))

static int check_test_events(FILE *fp)
{
	const test_event_t *e;
	char *fstr;
	uint64_t *codes;
	int count, i, j;
	int ret, errors = 0;

	for (i = 0, e = arm64_test_events; i < NUM_TEST_EVENTS; i++, e++) {
		codes = NULL;
		count = 0;
		fstr = NULL;
		ret = pfm_get_event_encoding(e->name, PFM_PLM0 | PFM_PLM3, &fstr, NULL, &codes, &count);
		if (ret != e->ret) {
			fprintf(fp,"Line %d, Event%d %s, ret=%s(%d) expected %s(%d)\n", e->line, i, e->name, pfm_strerror(ret), ret, pfm_strerror(e->ret), e->ret);
			errors++;
		} else {
			if (ret != PFM_SUCCESS) {
				if (fstr) {
					fprintf(fp,"Line %d, Event%d %s, expected fstr NULL but it is not\n", e->line, i, e->name);
					errors++;
				}
				if (count != 0) {
					fprintf(fp,"Line %d, Event%d %s, expected count=0 instead of %d\n", e->line, i, e->name, count);
					errors++;
				}
				if (codes) {
					fprintf(fp,"Line %d, Event%d %s, expected codes[] NULL but it is not\n", e->line, i, e->name);
					errors++;
				}
			} else {
				if (count != e->count) {
					fprintf(fp,"Line %d, Event%d %s, count=%d expected %d\n", e->line, i, e->name, count, e->count);
					errors++;
				}
				for (j=0; j < count; j++) {
					if (codes[j] != e->codes[j]) {
						fprintf(fp,"Line %d, Event%d %s, codes[%d]=%#"PRIx64" expected %#"PRIx64"\n", e->line, i, e->name, j, codes[j], e->codes[j]);
						errors++;
					}
				}
				if (e->fstr && strcmp(fstr, e->fstr)) {
					fprintf(fp,"Line %d, Event%d %s, fstr=%s expected %s\n", e->line, i, e->name, fstr, e->fstr);
					errors++;
				}
			}
		}
		if (codes)
			free(codes);
		if (fstr)
			free(fstr);
	}
	printf("\t %d ARM64 events: %d errors\n", i, errors);
	return errors;
}

int
validate_arch(FILE *fp)
{
	return check_test_events(fp);
}
