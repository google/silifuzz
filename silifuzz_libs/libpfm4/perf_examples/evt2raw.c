/*
 * evt2raw.c - example which converts an event string (event + modifiers) to
 * a raw event code usable by the perf tool.
 *
 * Copyright (c) 2010 IBM Corp.
 * Contributed by Corey Ashford <cjashfor@us.ibm.com>
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <perfmon/pfmlib_perf_event.h>

static void
usage(void)
{
	printf("usage: evt2raw [-v] <event>\n"
		"<event> is the symbolic event, including modifiers, to "
		"translate to a raw code.\n");
}

#define MAX_MODIFIER_CHARS 5  /* u,k,h plus the colon and null terminator */
int
main(int argc, char **argv)
{
	int ret, c, verbose = 0;
	struct perf_event_attr pea;
	char *event_str, *fstr = NULL;
	char modifiers[MAX_MODIFIER_CHARS];

	if (argc < 2) {
		usage();
		return 1;
	}
	while ( (c=getopt(argc, argv, "hv")) != -1) {
		switch(c) {
		case 'h':
			usage();
			exit(0);
		case 'v':
			verbose = 1;
			break;
		default:
			exit(1);
		}
	}
	event_str = argv[optind];

	ret = pfm_initialize();
	if (ret != PFM_SUCCESS)
		errx(1, "Internal error: pfm_initialize returned %s",
			pfm_strerror(ret));

	pea.size = sizeof(struct perf_event_attr);
	ret = pfm_get_perf_event_encoding(event_str, PFM_PLM0|PFM_PLM3|PFM_PLMH, &pea,
		&fstr, NULL);
	if (ret != PFM_SUCCESS)
		errx(1, "Error: pfm_get_perf_encoding returned %s",
			pfm_strerror(ret));

	if (pea.type != PERF_TYPE_RAW)
		errx(1, "Error: %s is not a raw hardware event", event_str);

	modifiers[0] = '\0';
	if (pea.exclude_user | pea.exclude_kernel | pea.exclude_hv) {
		strcat(modifiers, ":");
		if (!pea.exclude_user)
			strcat(modifiers, "u");
		if (!pea.exclude_kernel)
			strcat(modifiers, "k");
		if (!pea.exclude_hv)
			strcat(modifiers, "h");
	}

	if (verbose)
		printf("r%"PRIx64"%s\t%s\n", pea.config, modifiers, fstr);
	else
		printf("r%"PRIx64"%s\n", pea.config, modifiers);

	if (fstr)
		free(fstr);

	return 0;
}
