/*
 * validate.c - validate event tables + encodings
 *
 * Copyright (c) 2010 Google, Inc
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
 * This file is part of libpfm, a performance monitoring support library for
 * applications on Linux.
 */
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <perfmon/err.h>

#include <perfmon/pfmlib.h>
#ifdef __linux__
#include <perfmon/pfmlib_perf_event.h>
#endif

#define __weak_func	__attribute__((weak))

#ifdef PFMLIB_WINDOWS
int set_env_var(const char *var, const char *value, int ov)
{
	size_t len;
	char *str;
	int ret;

	len = strlen(var) + 1 + strlen(value) + 1;

	str = malloc(len);
	if (!str)
		return PFM_ERR_NOMEM;

	sprintf(str, "%s=%s", var, value);

	ret = putenv(str);

	free(str);

	return ret ? PFM_ERR_INVAL : PFM_SUCCESS;
}
#else
static inline int
set_env_var(const char *var, const char *value, int ov)
{
	return setenv(var, value, ov);
}
#endif

__weak_func int validate_arch(FILE *fp)
{
	return 0;
}

__weak_func int validate_perf(FILE *fp)
{
	return 0;
}


static struct {
	int valid_mode;
} options;

#define VALID_INTERN	0x1
#define VALID_ARCH	0x2
#define VALID_PERF	0x4
#define VALID_ALL	(VALID_INTERN|\
			 VALID_ARCH  |\
			 VALID_PERF)
static inline int
valid_mode(int f)
{
	return !!(options.valid_mode & f);
}

static void
usage(void)
{
	printf("validate [-c] [-a] [-A]"
#ifdef __linux__
		"[-p]"
#endif
		"\n"
		"-c\trun the library validate events\n"
		"-a\trun architecture specific event tests\n"
#ifdef __linux__
		"-p\trun perf_events specific event tests\n"
#endif
		"-A\trun all tests\n"
		"-h\tget help\n");
}

static int
validate_event_tables(void)
{
	pfm_pmu_info_t pinfo;
	pfm_pmu_t i;
	int ret, errors = 0;

	memset(&pinfo, 0, sizeof(pinfo));

	pinfo.size = sizeof(pinfo);

	pfm_for_all_pmus(i) {
		ret = pfm_get_pmu_info(i, &pinfo);
		if (ret != PFM_SUCCESS)
			continue;

		printf("\tchecking %s (%d events): ", pinfo.name, pinfo.nevents);
		fflush(stdout);

		ret = pfm_pmu_validate(i, stdout);
		if (ret != PFM_SUCCESS && ret != PFM_ERR_NOTSUPP) {
			printf("Failed\n");
			errors++;
		} else if (ret == PFM_ERR_NOTSUPP) {
			printf("N/A\n");
		} else {
			printf("Passed\n");
		}
	}
	return errors;
}

#if __WORDSIZE == 64
#define STRUCT_MULT	8
#else
#define STRUCT_MULT	4
#endif

#define MAX_FIELDS 32
typedef struct {
		const char *name;
		size_t sz;
} field_desc_t;

typedef struct {
	const char *name;
	size_t sz;
	size_t bitfield_sz;
	size_t abi_sz;
	field_desc_t fields[MAX_FIELDS];
} struct_desc_t;

#define LAST_STRUCT { .name = NULL, }

#define FIELD(n, st) \
	{ .name = #n, \
	  .sz   = sizeof(((st *)(0))->n), \
	}
#define LAST_FIELD { .name = NULL, }

static const struct_desc_t pfmlib_structs[]={
	{
	 .name = "pfm_pmu_info_t",
	 .sz   = sizeof(pfm_pmu_info_t),
	 .bitfield_sz = 4,
	 .abi_sz = PFM_PMU_INFO_ABI0,
	 .fields= {
		FIELD(name, pfm_pmu_info_t),
		FIELD(desc, pfm_pmu_info_t),
		FIELD(size, pfm_pmu_info_t),
		FIELD(pmu, pfm_pmu_info_t),
		FIELD(type, pfm_pmu_info_t),
		FIELD(nevents, pfm_pmu_info_t),
		FIELD(first_event, pfm_pmu_info_t),
		FIELD(max_encoding, pfm_pmu_info_t),
		FIELD(num_cntrs, pfm_pmu_info_t),
		FIELD(num_fixed_cntrs, pfm_pmu_info_t),
		LAST_FIELD
	 },
	},
	{
	 .name = "pfm_event_info_t",
	 .sz   = sizeof(pfm_event_info_t),
	 .bitfield_sz = 4,
	 .abi_sz = PFM_EVENT_INFO_ABI0,
	 .fields= {
		FIELD(name, pfm_event_info_t),
		FIELD(desc, pfm_event_info_t),
		FIELD(equiv, pfm_event_info_t),
		FIELD(size, pfm_event_info_t),
		FIELD(code, pfm_event_info_t),
		FIELD(pmu, pfm_event_info_t),
		FIELD(dtype, pfm_event_info_t),
		FIELD(idx, pfm_event_info_t),
		FIELD(nattrs, pfm_event_info_t),
		FIELD(reserved, pfm_event_info_t),
		LAST_FIELD
	 },
	},
	{
	 .name = "pfm_event_attr_info_t",
	 .sz   = sizeof(pfm_event_attr_info_t),
	 .bitfield_sz = 4+8,
	 .abi_sz = PFM_ATTR_INFO_ABI0,
	 .fields= {
		FIELD(name, pfm_event_attr_info_t),
		FIELD(desc, pfm_event_attr_info_t),
		FIELD(equiv, pfm_event_attr_info_t),
		FIELD(size, pfm_event_attr_info_t),
		FIELD(code, pfm_event_attr_info_t),
		FIELD(type, pfm_event_attr_info_t),
		FIELD(idx, pfm_event_attr_info_t),
		FIELD(ctrl, pfm_event_attr_info_t),
		LAST_FIELD
	 },
	},
	{
	 .name = "pfm_pmu_encode_arg_t",
	 .sz   = sizeof(pfm_pmu_encode_arg_t),
	 .abi_sz = PFM_RAW_ENCODE_ABI0,
	 .fields= {
		FIELD(codes, pfm_pmu_encode_arg_t),
		FIELD(fstr, pfm_pmu_encode_arg_t),
		FIELD(size, pfm_pmu_encode_arg_t),
		FIELD(count, pfm_pmu_encode_arg_t),
		FIELD(idx, pfm_pmu_encode_arg_t),
		LAST_FIELD
	 },
	},
#ifdef __linux__
	{
	 .name = "pfm_perf_encode_arg_t",
	 .sz   = sizeof(pfm_perf_encode_arg_t),
	 .bitfield_sz = 0,
	 .abi_sz = PFM_PERF_ENCODE_ABI0,
	 .fields= {
		FIELD(attr, pfm_perf_encode_arg_t),
		FIELD(fstr, pfm_perf_encode_arg_t),
		FIELD(size, pfm_perf_encode_arg_t),
		FIELD(idx, pfm_perf_encode_arg_t),
		FIELD(cpu, pfm_perf_encode_arg_t),
		FIELD(flags, pfm_perf_encode_arg_t),
		FIELD(pad0, pfm_perf_encode_arg_t),
		LAST_FIELD
	 },
	},
#endif
	LAST_STRUCT
};

static int
validate_structs(void)
{

	const struct_desc_t *d;
	const field_desc_t *f;
	size_t sz;
	int errors = 0;
	int abi = LIBPFM_ABI_VERSION;

	printf("\tlibpfm ABI version : %d\n", abi);
	for (d = pfmlib_structs; d->name; d++) {

		printf("\t%s : ", d->name);

		if (d->abi_sz != d->sz) {
			printf("struct size does not correspond to ABI size %zu vs. %zu)\n", d->abi_sz, d->sz);
			errors++;
		}

		if (d->sz % STRUCT_MULT) {
			printf("Failed (wrong mult size=%zu)\n", d->sz);
			errors++;
		}

		sz = d->bitfield_sz;
		for (f = d->fields; f->name; f++) {
			sz += f->sz;
		}

		if (sz != d->sz) {
			printf("Failed (invisible padding of %zu bytes, total struct size %zu bytes)\n", d->sz - sz, d->sz);
			errors++;
			continue;
		}
		printf("Passed\n");
		
	}
	return errors;
}

int
main(int argc, char **argv)
{
	int ret, c, errors = 0;


	while ((c=getopt(argc, argv,"hpcaA")) != -1) {
		switch(c) {
			case 'c':
				options.valid_mode |= VALID_INTERN;
				break;
			case 'a':
				options.valid_mode |= VALID_ARCH;
				break;
			case 'p':
				options.valid_mode |= VALID_PERF;
				break;
			case 'A':
				options.valid_mode |= VALID_ALL;
				break;
			case 'h':
				usage();
				exit(0);
			default:
				errx(1, "unknown option error");
		}
	}
	if (options.valid_mode == 0)
		options.valid_mode = VALID_ALL;

	/* to allow encoding of events from non detected PMU models */
	ret = set_env_var("LIBPFM_ENCODE_INACTIVE", "1", 1);
	if (ret != PFM_SUCCESS)
		errx(1, "cannot force inactive encoding");

	ret = pfm_initialize();
	if (ret != PFM_SUCCESS)
		errx(1, "cannot initialize libpfm: %s", pfm_strerror(ret));


	printf("Libpfm structure tests:\n");
	errors += validate_structs();

	if (valid_mode(VALID_PERF)) {
		printf("perf_events specific tests:\n");
		errors += validate_perf(stderr);
	}

	if (valid_mode(VALID_INTERN)) {
		printf("Libpfm internal table tests:\n");
		errors += validate_event_tables();
	}

	if (valid_mode(VALID_ARCH)) {
		printf("Architecture specific tests:\n");
		errors += validate_arch(stderr);
	}

	pfm_terminate();

	if (errors)
		printf("Total %d errors\n", errors);
	else
		printf("All tests passed\n");

	return errors;
}
