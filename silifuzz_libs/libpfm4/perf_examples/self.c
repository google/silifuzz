/*
 * self.c - example of a simple self monitoring task
 *
 * Copyright (c) 2009 Google, Inc
 * Contributed by Stephane Eranian <eranian@gmail.com>
 *
 * Based on:
 * Copyright (c) 2002-2007 Hewlett-Packard Development Company, L.P.
 * Contributed by Stephane Eranian <eranian@hpl.hp.com>
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
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <locale.h>
#include <sys/prctl.h>
#include <err.h>

#include <perfmon/pfmlib_perf_event.h>
#include "perf_util.h"

static const char *gen_events[]={
	"cycles:u",
	"instructions:u",
	NULL
};

static volatile int quit;
void sig_handler(int n)
{
	quit = 1;
}

void
noploop(void)
{
	for(;quit == 0;);
}

static void
print_counts(perf_event_desc_t *fds, int num_fds, const char *msg)
{
	uint64_t val;
	uint64_t values[3];
	double ratio;
	int i;
	ssize_t ret;

	/*
	 * now read the results. We use pfp_event_count because
	 * libpfm guarantees that counters for the events always
	 * come first.
	 */
	memset(values, 0, sizeof(values));

	for (i = 0; i < num_fds; i++) {

		ret = read(fds[i].fd, values, sizeof(values));
		if (ret < (ssize_t)sizeof(values)) {
			if (ret == -1)
				err(1, "cannot read results: %s", strerror(errno));
			else
				warnx("could not read event%d", i);
		}
		/*
		 * scaling is systematic because we may be sharing the PMU and
		 * thus may be multiplexed
		 */
		val = perf_scale(values);
		ratio = perf_scale_ratio(values);

		printf("%s %'20"PRIu64" %s (%.2f%% scaling, raw=%'"PRIu64", ena=%'"PRIu64", run=%'"PRIu64")\n",
			msg,
			val,
			fds[i].name,
			(1.0-ratio)*100.0,
		        values[0],
			values[1],
			values[2]);
	}
}

int
main(int argc, char **argv)
{
	perf_event_desc_t *fds = NULL;
	int i, ret, num_fds = 0;

	setlocale(LC_ALL, "");
	/*
	 * Initialize pfm library (required before we can use it)
	 */
	ret = pfm_initialize();
	if (ret != PFM_SUCCESS)
		errx(1, "Cannot initialize library: %s", pfm_strerror(ret));

	ret = perf_setup_argv_events(argc > 1 ? (const char **)argv+1 : gen_events, &fds, &num_fds);
	if (ret || !num_fds)
		errx(1, "cannot setup events");

	fds[0].fd = -1;
	for(i=0; i < num_fds; i++) {
		/* request timing information necessary for scaling */
		fds[i].hw.read_format = PERF_FORMAT_SCALE;

		fds[i].hw.disabled = 1; /* do not start now */

		/* each event is in an independent group (multiplexing likely) */
		fds[i].fd = perf_event_open(&fds[i].hw, 0, -1, -1, 0);
		if (fds[i].fd == -1)
			err(1, "cannot open event %d", i);
	}

	signal(SIGALRM, sig_handler);

	/*
	 * enable all counters attached to this thread and created by it
	 */
	ret = prctl(PR_TASK_PERF_EVENTS_ENABLE);
	if (ret)
		err(1, "prctl(enable) failed");

	print_counts(fds, num_fds, "INITIAL: ");

	alarm(10);

	noploop();

	/*
	 * disable all counters attached to this thread
	 */
	ret = prctl(PR_TASK_PERF_EVENTS_DISABLE);
	if (ret)
		err(1, "prctl(disable) failed");

	printf("Final counts:\n");
	print_counts(fds, num_fds, "FINAL:  ");

	for (i = 0; i < num_fds; i++)
	  close(fds[i].fd);

	perf_free_fds(fds, num_fds);

	/* free libpfm resources cleanly */
	pfm_terminate();

	return 0;
}
