/*
 * bts_smpl.c - example of Intel Branch Trace Stack sampling
 *
 * Copyright (c) 2009 Google, Inc
 * Contributed by Stephane Eranian <eranian@gmail.com>
 *
 * Based on:
 * Copyright (c) 2003-2006 Hewlett-Packard Development Company, L.P.
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
 */
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <stdarg.h>
#include <getopt.h>
#include <setjmp.h>
#include <limits.h>
#include <time.h>
#include <sys/time.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <err.h>

#include "perf_util.h"

#define SMPL_PERIOD	24000000ULL

typedef struct {
	int opt_no_show;
	int opt_inherit;
	int mmap_pages;
} options_t;

static jmp_buf jbuf;
static uint64_t collected_samples, lost_samples;
static perf_event_desc_t *fds;
static int num_fds;
static options_t options;

static struct option the_options[]={
	{ "help", 0, 0,  1},
	{ "no-show", 0, &options.opt_no_show, 1},
	{ 0, 0, 0, 0}
};

static void
cld_handler(int n)
{
	longjmp(jbuf, 1);
}

int
child(char **arg)
{
	/*
	 * force the task to stop before executing the first
	 * user level instruction
	 */
	ptrace(PTRACE_TRACEME, 0, NULL, NULL);

	execvp(arg[0], arg);
	/* not reached */
	return -1;
}

struct timeval last_read, this_read;

static void
process_smpl_buf(perf_event_desc_t *hw)
{
	struct perf_event_header ehdr;
	int ret;

	for(;;) {
		ret = perf_read_buffer(hw, &ehdr, sizeof(ehdr));
		if (ret)
			return; /* nothing to read */

		switch(ehdr.type) {
			case PERF_RECORD_SAMPLE:
				perf_display_sample(fds, num_fds, hw - fds, &ehdr, stdout);
				collected_samples++;
				break;
			case PERF_RECORD_EXIT:
				display_exit(hw, stdout);
				break;
			case PERF_RECORD_LOST:
				display_lost(hw, fds, num_fds, stdout);
				break;
			case PERF_RECORD_THROTTLE:
				display_freq(1, hw, stdout);
				break;
			case PERF_RECORD_UNTHROTTLE:
				display_freq(0, hw, stdout);
				break;
			default:
				printf("unknown sample type %d sz=%d\n", ehdr.type, ehdr.size);
				perf_skip_buffer(hw, ehdr.size - sizeof(ehdr));
		}
	}
}

int
mainloop(char **arg)
{
	static uint64_t ovfl_count; /* static to avoid setjmp issue */
	struct pollfd pollfds[1];
	size_t map_size = 0;
	sigset_t bmask;
	pid_t pid;
	uint64_t val[2];
	int status, ret;

	if (pfm_initialize() != PFM_SUCCESS)
		errx(1, "libpfm initialization failed\n");

	map_size = (options.mmap_pages+1)*getpagesize();

	/*
	 * does allocate fds
	 */
	ret = perf_setup_list_events("branches:u", &fds, &num_fds);
	if (ret || !num_fds)
		errx(1, "cannot setup event");

	memset(pollfds, 0, sizeof(pollfds));

	/*
	 * Create the child task
	 */
	if ((pid=fork()) == -1)
		err(1, "cannot fork process\n");

	if (pid == 0)
		exit(child(arg));

	/*
	 * wait for the child to exec
	 */
	ret = waitpid(pid, &status, WUNTRACED);
	if (ret == -1)
		err(1, "waitpid failed");

	if (WIFEXITED(status))
		errx(1, "task %s [%d] exited already status %d\n", arg[0], pid, WEXITSTATUS(status));

	fds[0].fd = -1;
	fds[0].hw.disabled = 0; /* start immediately */

	if (options.opt_inherit)
		fds[0].hw.inherit = 1;

	fds[0].hw.sample_type = PERF_SAMPLE_IP|PERF_SAMPLE_ADDR;

	/*
	 * BTS only supported at user level
	 */
	if (fds[0].hw.exclude_user ||fds[0].hw.exclude_kernel == 0)
		errx(1, "BTS currently supported only at the user level\n");

	/*
	 * period MUST be one to trigger BTS: tracing not sampling anymore
	 */
	fds[0].hw.sample_period = 1;
	fds[0].hw.exclude_kernel = 1;
	fds[0].hw.exclude_hv = 1;
	fds[0].hw.read_format |= PERF_FORMAT_ID;

	fds[0].fd = perf_event_open(&fds[0].hw, pid, -1, -1, 0);
	if (fds[0].fd == -1)
		err(1, "cannot attach event %s", fds[0].name);

	fds[0].buf = mmap(NULL, map_size, PROT_READ|PROT_WRITE, MAP_SHARED, fds[0].fd, 0);
	if (fds[0].buf == MAP_FAILED)
		err(1, "cannot mmap buffer");

	/* does not include header page */
	fds[0].pgmsk = (options.mmap_pages*getpagesize())-1;

	ret = read(fds[0].fd, val, sizeof(val));
	if (ret == -1)
		err(1, "cannot read id %zu", sizeof(val));

	fds[0].id = val[1];
	printf("%"PRIu64"  %s\n", fds[0].id, fds[0].name);

	/*
	 * effectively activate monitoring
	 */
	ptrace(PTRACE_DETACH, pid, NULL, 0);

	signal(SIGCHLD, cld_handler);

	pollfds[0].fd = fds[0].fd;
	pollfds[0].events = POLLIN;

	if (setjmp(jbuf) == 1)
		goto terminate_session;

	sigemptyset(&bmask);
	sigaddset(&bmask, SIGCHLD);
	/*
	 * core loop
	 */
	for(;;) {
		ret = poll(pollfds, 1, -1);
		if (ret < 0 && errno == EINTR)
			break;
		ovfl_count++;
		ret = sigprocmask(SIG_SETMASK, &bmask, NULL);
		if (ret)
			err(1, "setmask");
		process_smpl_buf(&fds[0]);
		ret = sigprocmask(SIG_UNBLOCK, &bmask, NULL);
		if (ret)
			err(1, "unblock");
	}
terminate_session:
	/*
	 * cleanup child
	 */
	wait4(pid, &status, 0, NULL);

	close(fds[0].fd);

	/* check for partial event buffer */
	process_smpl_buf(&fds[0]);
	munmap(fds[0].buf, map_size);

	free(fds);

	printf("%"PRIu64" samples collected in %"PRIu64" poll events, %"PRIu64" lost samples\n",
		collected_samples,
		ovfl_count, lost_samples);
	return 0;
}

static void
usage(void)
{
	printf("usage: bts_smpl [-h] [--help] [-i] [-m mmap_pages] cmd\n");
}

int
main(int argc, char **argv)
{
	int c;

	while ((c=getopt_long(argc, argv,"+hm:p:if", the_options, 0)) != -1) {
		switch(c) {
			case 0: continue;
			case 'i':
				options.opt_inherit = 1;
				break;
			case 'm':
				if (options.mmap_pages)
					errx(1, "mmap pages already set\n");
				options.mmap_pages = atoi(optarg);
				break;
			case 'h':
				usage();
				exit(0);
			default:
				errx(1, "unknown option");
		}
	}

	if (argv[optind] == NULL)
		errx(1, "you must specify a command to execute\n");

	if (!options.mmap_pages)
		options.mmap_pages = 4;
	
	return mainloop(argv+optind);
}
