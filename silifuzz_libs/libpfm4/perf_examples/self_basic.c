/*
 * self-basic.c - example of a simple self monitoring task no-helper
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
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <locale.h>
#include <sys/ioctl.h>
#include <err.h>

#include <perfmon/pfmlib_perf_event.h>

#define N 30

static unsigned long 
fib(unsigned long n)
{
	if (n == 0)
		return 0;
	if (n == 1)
		return 2;
	return fib(n-1)+fib(n-2);
}

int
main(int argc, char **argv)
{
	struct perf_event_attr attr;
	int fd, ret;
	uint64_t count = 0, values[3];

	setlocale(LC_ALL, "");

	/*
	 * Initialize libpfm library (required before we can use it)
	 */
	ret = pfm_initialize();
	if (ret != PFM_SUCCESS)
		errx(1, "cannot initialize library: %s", pfm_strerror(ret));

	memset(&attr, 0, sizeof(attr));

	/*
 	 * 1st argument: event string
 	 * 2nd argument: default privilege level (used if not specified in the event string)
 	 * 3rd argument: the perf_event_attr to initialize
 	 */
	ret = pfm_get_perf_event_encoding("cycles:u", PFM_PLM0|PFM_PLM3, &attr, NULL, NULL);
	if (ret != PFM_SUCCESS)
		errx(1, "cannot find encoding: %s", pfm_strerror(ret));

	/*
	 * request timing information because event may be multiplexed
	 * and thus it may not count all the time. The scaling information
	 * will be used to scale the raw count as if the event had run all
	 * along
	 */
	attr.read_format = PERF_FORMAT_TOTAL_TIME_ENABLED|PERF_FORMAT_TOTAL_TIME_RUNNING;

	/* do not start immediately after perf_event_open() */
	attr.disabled = 1;

	/*
 	 * create the event and attach to self
 	 * Note that it attaches only to the main thread, there is no inheritance
 	 * to threads that may be created subsequently.
 	 *
 	 * if mulithreaded, then getpid() must be replaced by gettid()
 	 */
	fd = perf_event_open(&attr, getpid(), -1, -1, 0);
	if (fd < 0) 
		err(1, "cannot create event");

	/*
 	 * start counting now
 	 */
	ret = ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
	if (ret)
		err(1, "ioctl(enable) failed");

	printf("Fibonacci(%d)=%lu\n", N, fib(N));

	/*
 	 * stop counting
 	 */
	ret = ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
	if (ret)
		err(1, "ioctl(disable) failed");

	/*
 	 * read the count + scaling values
 	 *
 	 * It is not necessary to stop an event to read its value
 	 */
	ret = read(fd, values, sizeof(values));
	if (ret != sizeof(values))
		err(1, "cannot read results: %s", strerror(errno));

	/*
 	 * scale count
	 *
	 * values[0] = raw count
	 * values[1] = TIME_ENABLED
	 * values[2] = TIME_RUNNING
 	 */
	if (values[2])
		count = (uint64_t)((double)values[0] * values[1]/values[2]);

	printf("count=%'"PRIu64"\n", count);

	close(fd);

	/* free libpfm resources cleanly */
	pfm_terminate();

	return 0;
}
