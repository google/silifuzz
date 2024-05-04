/*
 * validate_power.c - validate PowerPC event tables + encodings
 *
 * Copyright (c) 2012 Google, Inc
 * Contributed by Stephane Eranian <eranian@gmail.com>
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

static const test_event_t ppc_test_events[]={
	{ SRC_LINE,
	  .name = "ppc970::PM_CYC",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x7,
	  .fstr = "ppc970::PM_CYC",
	},
	{ SRC_LINE,
	  .name = "ppc970::PM_INST_DISP",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x320,
	  .fstr = "ppc970::PM_INST_DISP",
	},
	{ SRC_LINE,
	  .name = "ppc970mp::PM_CYC",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x7,
	  .fstr = "ppc970mp::PM_CYC",
	},
	{ SRC_LINE,
	  .name = "ppc970mp::PM_INST_DISP",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x320,
	  .fstr = "ppc970mp::PM_INST_DISP",
	},
	{ SRC_LINE,
	  .name = "power4::PM_CYC",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x7,
	  .fstr = "power4::PM_CYC",
	},
	{ SRC_LINE,
	  .name = "power4::PM_INST_DISP",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x221,
	  .fstr = "power4::PM_INST_DISP",
	},
	{ SRC_LINE,
	  .name = "power5::PM_CYC",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0xf,
	  .fstr = "power5::PM_CYC",
	},
	{ SRC_LINE,
	  .name = "power5::PM_INST_DISP",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x300009,
	  .fstr = "power5::PM_INST_DISP",
	},
	{ SRC_LINE,
	  .name = "power5p::PM_CYC",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0xf,
	  .fstr = "power5p::PM_CYC",
	},
	{ SRC_LINE,
	  .name = "power5p::PM_INST_DISP",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x300009,
	  .fstr = "power5p::PM_INST_DISP",
	},
	{ SRC_LINE,
	  .name = "power6::PM_INST_CMPL",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x2,
	  .fstr = "power6::PM_INST_CMPL",
	},
	{ SRC_LINE,
	  .name = "power6::PM_THRD_CONC_RUN_INST",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x300026,
	  .fstr = "power6::PM_THRD_CONC_RUN_INST",
	},
	{ SRC_LINE,
	  .name = "power7::PM_CYC",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x1e,
	  .fstr = "power7::PM_CYC",
	},
	{ SRC_LINE,
	  .name = "power7::PM_INST_DISP",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x200f2,
	  .fstr = "power7::PM_INST_DISP",
	},
	{ SRC_LINE,
	  .name = "power8::PM_L1MISS_LAT_EXC_1024",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x67200301eaull,
	  .fstr = "power8::PM_L1MISS_LAT_EXC_1024",
	},
	{ SRC_LINE,
	  .name = "power8::PM_RC_LIFETIME_EXC_32",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0xde200201e6ull,
	  .fstr = "power8::PM_RC_LIFETIME_EXC_32",
	},
	{ SRC_LINE,
	  .name = "power9::PM_CYC",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x1001e,
	  .fstr = "power9::PM_CYC",
	},
	{ SRC_LINE,
	  .name = "power9::PM_INST_DISP",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x200f2,
	  .fstr = "power9::PM_INST_DISP",
	},
	{ SRC_LINE,
	  .name = "power9::PM_CYC_ALT",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x2001e,
	  .fstr = "power9::PM_CYC_ALT",
	},
	{ SRC_LINE,
	  .name = "power9::PM_CYC_ALT2",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x3001e,
	  .fstr = "power9::PM_CYC_ALT2",
	},
	{ SRC_LINE,
	  .name = "power9::PM_INST_CMPL_ALT",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x20002,
	  .fstr = "power9::PM_INST_CMPL_ALT",
	},
	{ SRC_LINE,
	  .name = "power9::PM_L2_INST_MISS_ALT",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x4609e,
	  .fstr = "power9::PM_L2_INST_MISS_ALT",
	},
	{ SRC_LINE,
	  .name = "power9::PM_L2_INST_MISS",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x36880,
	  .fstr = "power9::PM_L2_INST_MISS",
	},
	{ SRC_LINE,
	  .name = "power10::PM_CYC",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x100f0,
	  .fstr = "power10::PM_CYC",
	},
	{ SRC_LINE,
	  .name = "power10::PM_CYC_ALT2",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x2001e,
	  .fstr = "power10::PM_CYC_ALT2",
	},
	{ SRC_LINE,
	  .name = "power10::PM_CYC_ALT3",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x3001e,
	  .fstr = "power10::PM_CYC_ALT3",
	},
	{ SRC_LINE,
	  .name = "power10::PM_INST_CMPL",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x100fe,
	  .fstr = "power10::PM_INST_CMPL",
	},
	{ SRC_LINE,
	  .name = "power10::PM_INST_CMPL_ALT2",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x20002,
	  .fstr = "power10::PM_INST_CMPL_ALT2",
	},
	{ SRC_LINE,
	  .name = "power10::PM_L2_INST",
	  .ret  = PFM_SUCCESS,
	  .count = 1,
	  .codes[0] = 0x36080,
	  .fstr = "power10::PM_L2_INST",
	},
	{ SRC_LINE,
	 .name = "powerpc_nest_mcs_read::MCS_00",
	 .ret = PFM_SUCCESS,
	 .count = 1,
	 .codes[0] = 0x118,
	 .fstr = "powerpc_nest_mcs_read::MCS_00",
	},
	{ SRC_LINE,
	 .name = "powerpc_nest_mcs_write::MCS_00",
	 .ret = PFM_SUCCESS,
	 .count = 1,
	 .codes[0] = 0x198,
	 .fstr = "powerpc_nest_mcs_write::MCS_00",
	},
};
#define NUM_TEST_EVENTS (int)(sizeof(ppc_test_events)/sizeof(test_event_t))

static int check_test_events(FILE *fp)
{
	const test_event_t *e;
	char *fstr;
	uint64_t *codes;
	int count, i, j;
	int ret, errors = 0;

	for (i = 0, e = ppc_test_events; i < NUM_TEST_EVENTS; i++, e++) {
		codes = NULL;
		count = 0;
		fstr = NULL;
		ret = pfm_get_event_encoding(e->name, PFM_PLM0 | PFM_PLM3, &fstr, NULL, &codes, &count);
		if (ret != e->ret) {
			fprintf(fp,"Event%d %s, ret=%s(%d) expected %s(%d)\n", i, e->name, pfm_strerror(ret), ret, pfm_strerror(e->ret), e->ret);
			errors++;
		} else {
			if (ret != PFM_SUCCESS) {
				if (fstr) {
					fprintf(fp,"Event%d %s, expected fstr NULL but it is not\n", i, e->name);
					errors++;
				}
				if (count != 0) {
					fprintf(fp,"Event%d %s, expected count=0 instead of %d\n", i, e->name, count);
					errors++;
				}
				if (codes) {
					fprintf(fp,"Event%d %s, expected codes[] NULL but it is not\n", i, e->name);
					errors++;
				}
			} else {
				if (count != e->count) {
					fprintf(fp,"Event%d %s, count=%d expected %d\n", i, e->name, count, e->count);
					errors++;
				}
				for (j=0; j < count; j++) {
					if (codes[j] != e->codes[j]) {
						fprintf(fp,"Event%d %s, codes[%d]=%#"PRIx64" expected %#"PRIx64"\n", i, e->name, j, codes[j], e->codes[j]);
						errors++;
					}
				}
				if (e->fstr && strcmp(fstr, e->fstr)) {
					fprintf(fp,"Event%d %s, fstr=%s expected %s\n", i, e->name, fstr, e->fstr);
					errors++;
				}
			}
		}
		if (codes)
			free(codes);
		if (fstr)
			free(fstr);
	}
	printf("\t %d PowerPC events: %d errors\n", i, errors);
	return errors;
}

int
validate_arch(FILE *fp)
{
	return check_test_events(fp);
}
