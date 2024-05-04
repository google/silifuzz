/*
 * showevtinfo.c - show event information
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
#include <regex.h>
#include <perfmon/err.h>

#include <perfmon/pfmlib.h>

#define MAXBUF		1024
#define COMBO_MAX	18

static struct {
	int compact;
	int sort;
	uint8_t encode;
	uint8_t combo;
	uint8_t combo_lim;
	uint8_t name_only;
	uint8_t desc;
	char *csv_sep;
	pfm_event_info_t efilter;
	pfm_event_attr_info_t ufilter;
	pfm_os_t os;
	uint64_t mask;
} options;

typedef struct {
	uint64_t code;
	int idx;
} code_info_t;

static void show_event_info_compact(pfm_event_info_t *info);

static const char *srcs[PFM_ATTR_CTRL_MAX]={
	[PFM_ATTR_CTRL_UNKNOWN] = "???",
	[PFM_ATTR_CTRL_PMU] = "PMU",
	[PFM_ATTR_CTRL_PERF_EVENT] = "perf_event",
};

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

static int
event_has_pname(char *s)
{
	char *p;
	return (p = strchr(s, ':')) && *(p+1) == ':';
}

static int
print_codes(char *buf, int plm, int max_encoding)
{
	uint64_t *codes = NULL;
	int j, ret, count = 0;

	ret = pfm_get_event_encoding(buf, PFM_PLM0|PFM_PLM3, NULL, NULL, &codes, &count);
	if (ret != PFM_SUCCESS) {
		if (ret == PFM_ERR_NOTFOUND)
			errx(1, "encoding failed, try setting env variable LIBPFM_ENCODE_INACTIVE=1");
		return -1;
	}
	for(j = 0; j < max_encoding; j++) {
		if (j < count)
			printf("0x%"PRIx64, codes[j]);
		printf("%s", options.csv_sep);
	}
	free(codes);
	return 0;
}

static int
check_valid(char *buf, int plm)
{
	uint64_t *codes = NULL;
	int ret, count = 0;

	ret = pfm_get_event_encoding(buf, PFM_PLM0|PFM_PLM3, NULL, NULL, &codes, &count);
	if (ret != PFM_SUCCESS)
		return -1;
	free(codes);
	return 0;
}

static int
match_ufilters(pfm_event_attr_info_t *info)
{
	uint32_t ufilter1 = 0;
	uint32_t ufilter2 = 0;

	if (options.ufilter.is_dfl)
		ufilter1 |= 0x1;

	if (info->is_dfl)
		ufilter2 |= 0x1;

	if (options.ufilter.is_precise)
		ufilter1 |= 0x2;

	if (info->is_precise)
		ufilter2 |= 0x2;

	if (!ufilter1)
		return 1;

	/* at least one filter matches */
	return ufilter1 & ufilter2;
}

static int
match_efilters(pfm_event_info_t *info)
{
	pfm_event_attr_info_t ainfo;
	int n = 0;
	int i, ret;

	if (options.efilter.is_precise && !info->is_precise)
		return 0;

	memset(&ainfo, 0, sizeof(ainfo));
	ainfo.size = sizeof(ainfo);

	pfm_for_each_event_attr(i, info) {
		ret = pfm_get_event_attr_info(info->idx, i, options.os, &ainfo);
		if (ret != PFM_SUCCESS)
			continue;
		if (match_ufilters(&ainfo))
			return 1;
                if (ainfo.type == PFM_ATTR_UMASK)
		        n++;
	}
	return n ? 0 : 1;
}

static void
show_event_info_combo(pfm_event_info_t *info)
{
	pfm_event_attr_info_t *ainfo;
	pfm_pmu_info_t pinfo;
	char buf[MAXBUF];
	size_t len;
	int numasks = 0;
	int i, j, ret;
	uint64_t total, m, u;

	memset(&pinfo, 0, sizeof(pinfo));

	pinfo.size = sizeof(pinfo);

	ret = pfm_get_pmu_info(info->pmu, &pinfo);
	if (ret != PFM_SUCCESS)
		errx(1, "cannot get PMU info");

	ainfo = calloc(info->nattrs, sizeof(*ainfo));
	if (!ainfo)
		err(1, "event %s : ", info->name);

	/*
	 * extract attribute information and count number
	 * of umasks
	 *
	 * we cannot just drop non umasks because we need
	 * to keep attributes in order for the enumeration
	 * of 2^n
	 */
	pfm_for_each_event_attr(i, info) {
		ainfo[i].size = sizeof(*ainfo);

		ret = pfm_get_event_attr_info(info->idx, i, options.os, &ainfo[i]);
		if (ret != PFM_SUCCESS)
			errx(1, "cannot get attribute info: %s", pfm_strerror(ret));

		if (ainfo[i].type == PFM_ATTR_UMASK)
			numasks++;
	}
	if (numasks > options.combo_lim) {
		warnx("event %s has too many umasks to print all combinations, dropping to simple enumeration", info->name);
		free(ainfo);
		show_event_info_compact(info);
		return;
	}

	if (numasks) {
		if (info->nattrs > (int)((sizeof(total)<<3))) {
			warnx("too many umasks, cannot show all combinations for event %s", info->name);
			goto end;
		}
		total = 1ULL << info->nattrs;

		for (u = 1; u < total; u++) {
			len = sizeof(buf);
			len -= snprintf(buf, len, "%s::%s", pinfo.name, info->name);
			if (len <= 0) {
				warnx("event name too long%s", info->name);
				goto end;
			}
			for(m = u, j = 0; m; m >>=1, j++) {
				if (m & 0x1ULL) {
					/* we have hit a non umasks attribute, skip */
					if (ainfo[j].type != PFM_ATTR_UMASK)
						break;

					if (len < (1 + strlen(ainfo[j].name))) {
						warnx("umasks combination too long for event %s", buf);
						break;
					}
					strncat(buf, ":", len-1);buf[len-1] = '\0'; len--;
					strncat(buf, ainfo[j].name, len-1);buf[len-1] = '\0';
					len -= strlen(ainfo[j].name);
				}
			}
			/* if found a valid umask combination, check encoding */
			if (m == 0) {
				if (options.encode)
					ret = print_codes(buf, PFM_PLM0|PFM_PLM3, pinfo.max_encoding);
				else
					ret = check_valid(buf, PFM_PLM0|PFM_PLM3);
				if (!ret)
					printf("%s\n", buf);
			}
		}
	} else {
		snprintf(buf, sizeof(buf)-1, "%s::%s", pinfo.name, info->name);
		buf[sizeof(buf)-1] = '\0';

		ret = options.encode ? print_codes(buf, PFM_PLM0|PFM_PLM3, pinfo.max_encoding) : 0;
		if (!ret)
			printf("%s\n", buf);
	}
end:
	free(ainfo);
}

static void
show_event_info_compact(pfm_event_info_t *info)
{
	pfm_event_attr_info_t ainfo;
	pfm_pmu_info_t pinfo;
	char buf[MAXBUF];
	int i, ret, um = 0;

	memset(&ainfo, 0, sizeof(ainfo));
	memset(&pinfo, 0, sizeof(pinfo));

	pinfo.size = sizeof(pinfo);
	ainfo.size = sizeof(ainfo);

	ret = pfm_get_pmu_info(info->pmu, &pinfo);
	if (ret != PFM_SUCCESS)
		errx(1, "cannot get pmu info: %s", pfm_strerror(ret));

	if (options.name_only) {
		if (options.encode)
			printf("0x%-10"PRIx64, info->code);
		printf("%s\n", info->name);
		return;
	}
	pfm_for_each_event_attr(i, info) {
		ret = pfm_get_event_attr_info(info->idx, i, options.os, &ainfo);
		if (ret != PFM_SUCCESS)
			errx(1, "cannot get attribute info: %s", pfm_strerror(ret));

		if (ainfo.type != PFM_ATTR_UMASK)
			continue;

		if (!match_ufilters(&ainfo))
			continue;

		snprintf(buf, sizeof(buf)-1, "%s::%s:%s", pinfo.name, info->name, ainfo.name);
		buf[sizeof(buf)-1] = '\0';

		ret = 0;
		if (options.encode) {
			ret = print_codes(buf, PFM_PLM0|PFM_PLM3, pinfo.max_encoding);
		}
		if (!ret) {
			printf("%s", buf);
			if (options.desc) {
				printf("%s", options.csv_sep);
				printf("\"%s. %s.\"", info->desc, ainfo.desc);
			}
			putchar('\n');
		}
		um++;
	}
	if (um == 0) {
		if (!match_efilters(info))
			return;

		snprintf(buf, sizeof(buf)-1, "%s::%s", pinfo.name, info->name);
		buf[sizeof(buf)-1] = '\0';
		if (options.encode) {
			ret = print_codes(buf, PFM_PLM0|PFM_PLM3, pinfo.max_encoding);
			if (ret)
				return;
		}
		printf("%s", buf);
		if (options.desc) {
			printf("%s", options.csv_sep);
			printf("\"%s.\"", info->desc);
		}
		putchar('\n');
	}
}

int compare_codes(const void *a, const void *b)
{
	const code_info_t *aa = a;
	const code_info_t *bb = b;
	uint64_t m = options.mask;

	if ((aa->code & m) < (bb->code &m))
		return -1;
	if ((aa->code & m) == (bb->code & m))
		return 0;
	return 1;
}

static void
print_event_flags(pfm_event_info_t *info)
{
	int n = 0;
	int spec = info->is_speculative;

	if (info->is_precise) {
		printf("[precise] ");
		n++;
	}

	if (info->support_hw_smpl) {
		printf("[hw_smpl] ");
		n++;
	}

	if (spec > PFM_EVENT_INFO_SPEC_NA) {
		printf("[%s] ", spec == PFM_EVENT_INFO_SPEC_TRUE ? "speculative" : "non-speculative");
		n++;
	}

	if (!n)
		printf("None");
}

static void
print_attr_flags(pfm_event_attr_info_t *info)
{
	int n = 0;
	int spec = info->is_speculative;

	if (info->is_dfl) {
		printf("[default] ");
		n++;
	}

	if (info->is_precise) {
		printf("[precise] ");
		n++;
	}

	if (info->support_hw_smpl) {
		printf("[hw_smpl] ");
		n++;
	}

	if (spec > PFM_EVENT_INFO_SPEC_NA) {
		printf("[%s] ", spec == PFM_EVENT_INFO_SPEC_TRUE ? "speculative" : "non-speculative");
		n++;
	}

	if (!n)
		printf("None ");
}


static void
show_event_info(pfm_event_info_t *info)
{
	pfm_event_attr_info_t ainfo;
	pfm_pmu_info_t pinfo;
	int mod = 0, um = 0;
	int i, ret;
	const char *src;

	if (options.name_only) {
		printf("%s\n", info->name);
		return;
	}

	memset(&ainfo, 0, sizeof(ainfo));
	memset(&pinfo, 0, sizeof(pinfo));

	pinfo.size = sizeof(pinfo);
	ainfo.size = sizeof(ainfo);

	if (!match_efilters(info))
		return;
	ret = pfm_get_pmu_info(info->pmu, &pinfo);
	if (ret)
		errx(1, "cannot get pmu info: %s", pfm_strerror(ret));

	printf("#-----------------------------\n"
	       "IDX	 : %d\n"
	       "PMU name : %s (%s)\n"
	       "Name     : %s\n"
	       "Equiv	 : %s\n",
		info->idx,
		pinfo.name,
		pinfo.desc,
		info->name,
		info->equiv ? info->equiv : "None");

	printf("Flags    : ");
	print_event_flags(info);
	putchar('\n');

	printf("Desc     : %s\n", info->desc ? info->desc : "no description available");
	printf("Code     : 0x%"PRIx64"\n", info->code);

	pfm_for_each_event_attr(i, info) {
		ret = pfm_get_event_attr_info(info->idx, i, options.os, &ainfo);
		if (ret != PFM_SUCCESS)
			errx(1, "cannot retrieve event %s attribute info: %s", info->name, pfm_strerror(ret));

		if (ainfo.ctrl >= PFM_ATTR_CTRL_MAX) {
			warnx("event: %s has unsupported attribute source %d", info->name, ainfo.ctrl);
			ainfo.ctrl = PFM_ATTR_CTRL_UNKNOWN;
		}
		src = srcs[ainfo.ctrl];
		switch(ainfo.type) {
		case PFM_ATTR_UMASK:
			if (!match_ufilters(&ainfo))
				continue;

			printf("Umask-%02u : 0x%02"PRIx64" : %s : [%s] : ",
				um,
				ainfo.code,
				src,
				ainfo.name);

			print_attr_flags(&ainfo);

			putchar(':');

			if (ainfo.equiv)
				printf(" Alias to %s", ainfo.equiv);
			else
				printf(" %s", ainfo.desc);

			putchar('\n');
			um++;
			break;
		case PFM_ATTR_MOD_BOOL:
			printf("Modif-%02u : 0x%02"PRIx64" : %s : [%s] : %s (boolean)\n", mod, ainfo.code, src, ainfo.name, ainfo.desc);
			mod++;
			break;
		case PFM_ATTR_MOD_INTEGER:
			printf("Modif-%02u : 0x%02"PRIx64" : %s : [%s] : %s (integer)\n", mod, ainfo.code, src, ainfo.name, ainfo.desc);
			mod++;
			break;
		default:
			printf("Attr-%02u  : 0x%02"PRIx64" : %s : [%s] : %s\n", i, ainfo.code, ainfo.name, src, ainfo.desc);
		}
	}
}


static int
show_info(char *event, regex_t *preg)
{
	pfm_pmu_info_t pinfo;
	pfm_event_info_t info;
	pfm_pmu_t j;
	int i, ret, match = 0, pname;
	size_t len, l = 0;
	char *fullname = NULL;

	memset(&pinfo, 0, sizeof(pinfo));
	memset(&info, 0, sizeof(info));

	pinfo.size = sizeof(pinfo);
	info.size = sizeof(info);

	pname = event_has_pname(event);

	/*
	 * scan all supported events, incl. those
	 * from undetected PMU models
	 */
	pfm_for_all_pmus(j) {

		ret = pfm_get_pmu_info(j, &pinfo);
		if (ret != PFM_SUCCESS)
			continue;

		/* no pmu prefix, just look for detected PMU models */
		if (!pname && !pinfo.is_present)
			continue;

		for (i = pinfo.first_event; i != -1; i = pfm_get_event_next(i)) {
			ret = pfm_get_event_info(i, options.os, &info);
			if (ret != PFM_SUCCESS)
				errx(1, "cannot get event info: %s", pfm_strerror(ret));

			len = strlen(info.name) + strlen(pinfo.name) + 1 + 2;
			if (len > l) {
				l = len;
				fullname = realloc(fullname, l);
				if (!fullname)
					err(1, "cannot allocate memory");
			}
			sprintf(fullname, "%s::%s", pinfo.name, info.name);

			if (regexec(preg, fullname, 0, NULL, 0) == 0) {
				 if (options.compact)
					if (options.combo)
						show_event_info_combo(&info);
					else
						show_event_info_compact(&info);
				else
					show_event_info(&info);
				match++;
			}
		}
	}
	if (fullname)
		free(fullname);

	return match;
}

	static int
show_info_sorted(char *event, regex_t *preg)
{
	pfm_pmu_info_t pinfo;
	pfm_event_info_t info;
	pfm_pmu_t j;
	int i, ret, n, match = 0;
	size_t len, l = 0;
	char *fullname = NULL;
	code_info_t *codes;

	memset(&pinfo, 0, sizeof(pinfo));
	memset(&info, 0, sizeof(info));

	pinfo.size = sizeof(pinfo);
	info.size = sizeof(info);

	pfm_for_all_pmus(j) {

		ret = pfm_get_pmu_info(j, &pinfo);
		if (ret != PFM_SUCCESS)
			continue;

		codes = malloc(pinfo.nevents * sizeof(*codes));
		if (!codes)
			err(1, "cannot allocate memory\n");

		/* scans all supported events */
		n = 0;
		for (i = pinfo.first_event; i != -1; i = pfm_get_event_next(i)) {

			ret = pfm_get_event_info(i, options.os, &info);
			if (ret != PFM_SUCCESS)
				errx(1, "cannot get event info: %s", pfm_strerror(ret));

			if (info.pmu != j)
				continue;

			codes[n].idx = info.idx;
			codes[n].code = info.code;
			n++;
		}
		qsort(codes, n, sizeof(*codes), compare_codes);
		for(i=0; i < n; i++) {
			ret = pfm_get_event_info(codes[i].idx, options.os, &info);
			if (ret != PFM_SUCCESS)
				errx(1, "cannot get event info: %s", pfm_strerror(ret));

			len = strlen(info.name) + strlen(pinfo.name) + 1 + 2;
			if (len > l) {
				l = len;
				fullname = realloc(fullname, l);
				if (!fullname)
					err(1, "cannot allocate memory");
			}
			sprintf(fullname, "%s::%s", pinfo.name, info.name);

			if (regexec(preg, fullname, 0, NULL, 0) == 0) {
				if (options.compact)
					show_event_info_compact(&info);
				else
					show_event_info(&info);
				match++;
			}
		}
		free(codes);
	}
	if (fullname)
		free(fullname);

	return match;
}

	static void
usage(void)
{
	printf("showevtinfo [-L] [-E] [-h] [-s] [-m mask]\n"
			"-L\t\tlist one event per line (compact mode)\n"
			"-E\t\tlist one event per line with encoding (compact mode)\n"
			"-M\t\tdisplay all valid unit masks combination (use with -L or -E)\n"
			"-h\t\tget help\n"
			"-s\t\tsort event by PMU and by code based on -m mask\n"
			"-l\t\tmaximum number of umasks to list all combinations (default: %d)\n"
			"-F\t\tshow only events and attributes with certain flags (precise,...)\n"
			"-m mask\t\thexadecimal event code mask, bits to match when sorting\n"
			"-x sep\t\tuse sep as field separator in compact mode\n"
			"-D\t\t\tprint event description in compact mode\n"
			"-O os\t\tshow attributes for the specific operating system\n",
			COMBO_MAX);
}

/*
 * keep: [pmu::]event
 * drop everything else
 */
	static void
drop_event_attributes(char *str)
{
	char *p;

	p = strchr(str, ':');
	if (!p)
		return;

	str = p+1;
	/* keep PMU name */
	if (*str == ':')
		str++;

	/* stop string at 1st attribute */
	p = strchr(str, ':');
	if (p)
		*p = '\0';
}

#define EVENT_FLAGS(n, f, l) { .name = n, .ebit = f, .ubit = l }
struct attr_flags {
	const char *name;
	int ebit; /* bit position in pfm_event_info_t.flags, -1 means ignore */
	int ubit; /*  bit position in pfm_event_attr_info_t.flags, -1 means ignore */
};

static const struct attr_flags  event_flags[]={
	EVENT_FLAGS("precise", 0, 1),
	EVENT_FLAGS("pebs", 0, 1),
	EVENT_FLAGS("default", -1, 0),
	EVENT_FLAGS("dfl", -1, 0),
	EVENT_FLAGS(NULL, 0, 0)
};

static void
parse_filters(char *arg)
{
	const struct attr_flags *attr;
	char *p;

	while (arg) {
		p = strchr(arg, ',');
		if (p)
			*p++ = 0;

		for (attr = event_flags; attr->name; attr++) {
			if (!strcasecmp(attr->name, arg)) {
				switch(attr->ebit) {
				case 0:
					options.efilter.is_precise = 1;
					break;
				case -1:
					break;
				default:
					errx(1, "unknown event flag %d", attr->ebit);
				}
				switch (attr->ubit) {
				case 0:
					options.ufilter.is_dfl = 1;
					break;
				case 1:
					options.ufilter.is_precise = 1;
					break;
				case -1:
					break;
				default:
					errx(1, "unknown umaks flag %d", attr->ubit);
				}
				break;
			}
		}
		arg = p;
	}
}

static const struct {
	char *name;
	pfm_os_t os;
} supported_oses[]={
	{ .name = "none", .os = PFM_OS_NONE },
	{ .name = "raw", .os = PFM_OS_NONE },
	{ .name = "pmu", .os = PFM_OS_NONE },

	{ .name = "perf", .os = PFM_OS_PERF_EVENT},
	{ .name = "perf_ext", .os = PFM_OS_PERF_EVENT_EXT},
	{ .name = NULL, }
};

static const char *pmu_types[]={
	"unknown type",
	"core",
	"uncore",
	"OS generic",
};

static void
setup_os(char *ostr)
{
	int i;

	for (i = 0; supported_oses[i].name; i++) {
		if (!strcmp(supported_oses[i].name, ostr)) {
			options.os = supported_oses[i].os;
			return;
		}
	}
	fprintf(stderr, "unknown OS layer %s, choose from:", ostr);
	for (i = 0; supported_oses[i].name; i++) {
		if (i)
			fputc(',', stderr);
		fprintf(stderr, " %s", supported_oses[i].name);
	}
	fputc('\n', stderr);
	exit(1);
}

int
main(int argc, char **argv)
{
	static char *argv_all[2] = { ".*", NULL };
	pfm_pmu_info_t pinfo;
	char *endptr = NULL;
	char default_sep[2] = "\t";
	char *ostr = NULL;
	char **args;
	pfm_pmu_t i;
	int match;
	regex_t preg;
	int ret, c;

	memset(&pinfo, 0, sizeof(pinfo));

	pinfo.size = sizeof(pinfo);

	while ((c=getopt(argc, argv,"hELsm:MNl:F:x:DO:")) != -1) {
		switch(c) {
			case 'L':
				options.compact = 1;
				break;
			case 'F':
				parse_filters(optarg);
				break;
			case 'E':
				options.compact = 1;
				options.encode = 1;
				break;
			case 'M':
				options.combo = 1;
				break;
			case 'N':
				options.name_only = 1;
				break;
			case 's':
				options.sort = 1;
				break;
			case 'D':
				options.desc = 1;
				break;
			case 'l':
				options.combo_lim = atoi(optarg);
				break;
			case 'x':
				options.csv_sep = optarg;
				break;
			case 'O':
				ostr = optarg;
				break;
			case 'm':
				options.mask = strtoull(optarg, &endptr, 16);
				if (*endptr)
					errx(1, "mask must be in hexadecimal\n");
				break;
			case 'h':
				usage();
				exit(0);
			default:
				errx(1, "unknown option error");
		}
	}
	/* to allow encoding of events from non detected PMU models */
	ret = set_env_var("LIBPFM_ENCODE_INACTIVE", "1", 1);
	if (ret != PFM_SUCCESS)
		errx(1, "cannot force inactive encoding");


	ret = pfm_initialize();
	if (ret != PFM_SUCCESS)
		errx(1, "cannot initialize libpfm: %s", pfm_strerror(ret));

	if (options.mask == 0)
		options.mask = ~0;

	if (optind == argc) {
		args = argv_all;
	} else {
		args = argv + optind;
	}
	if (!options.csv_sep)
		options.csv_sep = default_sep;

	/* avoid combinatorial explosion */
	if (options.combo_lim == 0)
		options.combo_lim = COMBO_MAX;

	if (ostr)
		setup_os(ostr);
	else
		options.os = PFM_OS_NONE;

	if (!options.compact) {
		int total_supported_events = 0;
		int total_available_events = 0;

		printf("Supported PMU models:\n");
		pfm_for_all_pmus(i) {
			ret = pfm_get_pmu_info(i, &pinfo);
			if (ret != PFM_SUCCESS)
				continue;

			printf("\t[%d, %s, \"%s\"]\n", i, pinfo.name,  pinfo.desc);
		}

		printf("Detected PMU models:\n");
		pfm_for_all_pmus(i) {
			ret = pfm_get_pmu_info(i, &pinfo);
			if (ret != PFM_SUCCESS)
				continue;

			if (pinfo.is_present) {
				if (pinfo.type >= PFM_PMU_TYPE_MAX)
					pinfo.type = PFM_PMU_TYPE_UNKNOWN;

				printf("\t[%d, %s, \"%s\", %d events, %d max encoding, %d counters, %s PMU]\n",
				       i,
				       pinfo.name,
				       pinfo.desc,
				       pinfo.nevents,
				       pinfo.max_encoding,
				       pinfo.num_cntrs + pinfo.num_fixed_cntrs,
				       pmu_types[pinfo.type]);

				total_supported_events += pinfo.nevents;
			}
			total_available_events += pinfo.nevents;
		}
		printf("Total events: %d available, %d supported\n", total_available_events, total_supported_events);
	}

	while(*args) {
		/* drop umasks and modifiers */
		drop_event_attributes(*args);
		if (regcomp(&preg, *args, REG_ICASE))
			errx(1, "error in regular expression for event \"%s\"", *argv);

		if (options.sort)
			match = show_info_sorted(*args, &preg);
		else
			match = show_info(*args, &preg);

		if (match == 0)
			errx(1, "event %s not found", *args);

		args++;
	}

	regfree(&preg);

	pfm_terminate();

	return 0;
}
