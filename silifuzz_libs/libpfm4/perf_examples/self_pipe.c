/*
 * self_pipe.c - dual process ping-pong example to stress PMU context switch of one process
 *
 * Copyright (c) 2008 Google, Inc
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
#include <signal.h>
#include <sched.h>
#include <err.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>

#include <perfmon/pfmlib_perf_event.h>

#include "perf_util.h"

static struct {
	const char *events;
	int cpu;
	int delay;
} options;

int
pin_cpu(pid_t pid, unsigned int cpu)
{
	cpu_set_t mask;
	CPU_ZERO(&mask);
	CPU_SET(cpu, &mask);

	return sched_setaffinity(pid, sizeof(mask), &mask);
}


static volatile int quit;
void sig_handler(int n)
{
	quit = 1;
}

static void
do_child(int fr, int fw)
{
	char c;
	ssize_t ret;

	for(;;) {
		ret = read(fr, &c, 1);	
		if (ret < 0)
			break;
		ret = write(fw, "c", 1);
		if (ret < 0)
			break;
		
	}
	printf("child exited\n");
	exit(0);
}

static void
measure(void)
{
	perf_event_desc_t *fds = NULL;
	int num_fds = 0;
	uint64_t values[3];
	ssize_t n;
	int i, ret;
	int pr[2], pw[2];
	pid_t pid;
	char cc = '0';

	ret = pfm_initialize();
	if (ret != PFM_SUCCESS)
		err(1, "cannot initialize libpfm");

	if (options.cpu == -1) {
		srandom(getpid());
		options.cpu = random() % sysconf(_SC_NPROCESSORS_ONLN);
	}

	ret = pipe(pr);
	if (ret)
		err(1, "cannot create read pipe");

	ret = pipe(pw);
	if (ret)
		err(1, "cannot create write pipe");

	ret = perf_setup_list_events(options.events, &fds, &num_fds);
	if (ret || !num_fds)
		exit(1);

	for(i=0; i < num_fds; i++) {
		fds[i].hw.disabled = 1;
		fds[i].hw.read_format = PERF_FORMAT_SCALE;

		fds[i].fd = perf_event_open(&fds[i].hw, 0, -1, -1, 0);
		if (fds[i].fd == -1)
			err(1, "cannot open event %d", i);
	}

	/*
 	 * Pin to CPU0, inherited by child process. That will enforce
 	 * the ping-pionging and thus stress the PMU context switch 
 	 * which is what we want
 	 */
	ret = pin_cpu(getpid(), options.cpu);
	if (ret)
		err(1, "cannot pin to CPU%d", options.cpu);

	printf("Both processes pinned to CPU%d, running for %d seconds\n", options.cpu, options.delay);

	/*
 	 * create second process which is not monitoring at the moment
 	 */
	switch(pid=fork()) {
		case -1:
			err(1, "cannot create child\n");
			exit(1); /* not reached */
		case 0:
			/* do not inherit session fd */
			for(i=0; i < num_fds; i++)
				close(fds[i].fd);
			/* pr[]: write master, read child */
			/* pw[]: read master, write child */
			close(pr[1]); close(pw[0]);
			do_child(pr[0], pw[1]);
			exit(1);
	}

	close(pr[0]);
	close(pw[1]);

	/*
	 * Let's roll now
	 */
	prctl(PR_TASK_PERF_EVENTS_ENABLE);
	signal(SIGALRM, sig_handler);
	alarm(options.delay);

	/*
	 * ping pong loop
	 */
	while(!quit) {
		n = write(pr[1], "c", 1);
		if (n < 1)
			err(1, "write failed");
		n = read(pw[0], &cc, 1);
		if (n < 1)
			err(1, "read failed");
	}

	prctl(PR_TASK_PERF_EVENTS_DISABLE);

	for(i=0; i < num_fds; i++) {
		uint64_t val;
		double ratio;

		ret = read(fds[i].fd, values, sizeof(values));
		if (ret == -1)
			err(1,"pfm_read error");
		if (ret != sizeof(values))
			errx(1, "did not read correct amount %d", ret);

		val = perf_scale(values);
		ratio = perf_scale_ratio(values);

		if (ratio == 1.0)
			printf("%20"PRIu64" %s\n", val, fds[i].name);
		else
			if (ratio == 0.0)
				printf("%20"PRIu64" %s (did not run: competing session)\n", val, fds[i].name);
			else
				printf("%20"PRIu64" %s (scaled from %.2f%% of time)\n", val, fds[i].name, ratio*100.0);
	}
	/*
	 * kill child process
	 */
	kill(SIGKILL, pid);

	/*
 	 * close pipes
 	 */
	close(pr[1]);
	close(pw[0]);
	/*
	 * and destroy our session
	 */
	for(i=0; i < num_fds; i++)
		close(fds[i].fd);

	perf_free_fds(fds, num_fds);

	/* free libpfm resources cleanly */
	pfm_terminate();
}

static void
usage(void)
{
	printf("usage: self_pipe [-h] [-c cpu] [-d delay] [-e event1,event2,...]\n");
}

int
main(int argc, char **argv)
{
	int c;

	options.cpu = -1;
	options.delay = -1;

	while ((c=getopt(argc, argv,"he:c:d:")) != -1) {
		switch(c) {
			case 'e':
				options.events = optarg;
				break;
			case 'c':
				options.cpu = atoi(optarg);
				break;
			case 'd':
				options.delay = atoi(optarg);
				break;
			case 'h':
				usage();
				exit(0);
			default:
				errx(1, "unknown error");
		}
	}
	if (!options.events)
		options.events = "cycles:u,instructions:u";

	if (options.delay == -1)
		options.delay = 10;

	measure();

	return 0;
}
