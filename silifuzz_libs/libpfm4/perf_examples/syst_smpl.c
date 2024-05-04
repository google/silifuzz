/*
 * syst_smpl.c - example of a system-wide sampling
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
 */
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <setjmp.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <err.h>
#include <locale.h>

#include "perf_util.h"

#define SMPL_PERIOD	240000000ULL

#define MAX_PATH	1024
#ifndef STR
# define _STR(x) #x
# define STR(x) _STR(x)
#endif

typedef struct {
	int opt_no_show;
	int mmap_pages;
	int cpu;
	int pin;
	int delay;
	char *events;
	char *cgroup;
} options_t;

static jmp_buf jbuf;
static uint64_t collected_samples, lost_samples;
static perf_event_desc_t *fds;
static int num_fds;
static options_t options;
static size_t pgsz;
static size_t map_size;

static struct option the_options[]={
	{ "help", 0, 0,  1},
	{ "no-show", 0, &options.opt_no_show, 1},
	{ 0, 0, 0, 0}
};

static const char *gen_events = "cycles,instructions";

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
				ret = perf_display_sample(fds, num_fds, hw - fds, &ehdr, stdout);
				if (ret)
					errx(1, "cannot parse sample");
				collected_samples++;
				break;
			case PERF_RECORD_EXIT:
				display_exit(hw, stdout);
				break;
			case PERF_RECORD_LOST:
				lost_samples += display_lost(hw, fds, num_fds, stdout);
				break;
			case PERF_RECORD_THROTTLE:
				display_freq(1, hw, stdout);
				break;
			case PERF_RECORD_UNTHROTTLE:
				display_freq(0, hw, stdout);
				break;
			default:
				printf("unknown sample type %d\n", ehdr.type);
				perf_skip_buffer(hw, ehdr.size - sizeof(ehdr));
		}
	}
}

int
setup_cpu(int cpu, int fd)
{
	int ret, flags;
	int i, pid;

	/*
	 * does allocate fds
	 */
	ret = perf_setup_list_events(options.events, &fds, &num_fds);
	if (ret || !num_fds)
		errx(1, "cannot setup event list");

	if (!fds[0].hw.sample_period)
		errx(1, "need to set sampling period or freq on first event, use :period= or :freq=");

	fds[0].fd = -1;
	for(i=0; i < num_fds; i++) {

		fds[i].hw.disabled = !i; /* start immediately */

		if (options.cgroup) {
			flags = PERF_FLAG_PID_CGROUP;
			pid = fd;
		} else {
			flags = 0;
			pid = -1;
		}

		if (options.pin)
			fds[i].hw.pinned = 1;

		if (fds[i].hw.sample_period) {
			/*
			 * set notification threshold to be halfway through the buffer
			 */
			if (fds[i].hw.sample_period) {
				fds[i].hw.wakeup_watermark = (options.mmap_pages*pgsz) / 2;
				fds[i].hw.watermark = 1;
			}

			fds[i].hw.sample_type = PERF_SAMPLE_IP|PERF_SAMPLE_TID|PERF_SAMPLE_READ|PERF_SAMPLE_TIME|PERF_SAMPLE_PERIOD|PERF_SAMPLE_STREAM_ID|PERF_SAMPLE_CPU;
			/*
			 * if we have more than one event, then record event identifier to help with parsing
			 */
			if (num_fds > 1)
				fds[i].hw.sample_type |= PERF_SAMPLE_IDENTIFIER;

			printf("%s period=%"PRIu64" freq=%d\n", fds[i].name, fds[i].hw.sample_period, fds[i].hw.freq);

			fds[i].hw.read_format = PERF_FORMAT_SCALE;

			if (fds[i].hw.freq)
				fds[i].hw.sample_type |= PERF_SAMPLE_PERIOD;
		}

		fds[i].fd = perf_event_open(&fds[i].hw, pid, cpu, fds[0].fd, flags);
		if (fds[i].fd == -1) {
			if (fds[i].hw.precise_ip)
				err(1, "cannot attach event %s: precise mode may not be supported", fds[i].name);
			err(1, "cannot attach event %s", fds[i].name);
		}
	}

	/*
	 * kernel adds the header page to the size of the mmapped region
	 */
	fds[0].buf = mmap(NULL, map_size, PROT_READ|PROT_WRITE, MAP_SHARED, fds[0].fd, 0);
	if (fds[0].buf == MAP_FAILED)
		err(1, "cannot mmap buffer");

	/* does not include header page */
	fds[0].pgmsk = (options.mmap_pages*pgsz)-1;

	/*
	 * send samples for all events to first event's buffer
	 */
	for (i = 1; i < num_fds; i++) {
		if (!fds[i].hw.sample_period)
			continue;
		ret = ioctl(fds[i].fd, PERF_EVENT_IOC_SET_OUTPUT, fds[0].fd);
		if (ret)
			err(1, "cannot redirect sampling output");
	}

	/*
	 * collect event ids
	 */
	if (num_fds > 1 && fds[0].fd > -1) {
		for(i = 0; i < num_fds; i++) {
			/*
			 * read the event identifier using ioctl
			 * new method replaced the trick with PERF_FORMAT_GROUP + PERF_FORMAT_ID + read()
			 */
			ret = ioctl(fds[i].fd, PERF_EVENT_IOC_ID, &fds[i].id);
			if (ret == -1)
				err(1, "cannot read ID");
			printf("ID %"PRIu64"  %s\n", fds[i].id, fds[i].name);
		}
	}
	return 0;
}

static void
start_cpu(void)
{
	int ret;

	ret = ioctl(fds[0].fd, PERF_EVENT_IOC_ENABLE, 0);
	if (ret)
		err(1, "cannot start counter");
}

static int
cgroupfs_find_mountpoint(char *buf, size_t maxlen)
{
	FILE *fp;
	char mountpoint[MAX_PATH+1], tokens[MAX_PATH+1], type[MAX_PATH+1];
	char *token, *saved_ptr = NULL;
	int found = 0;

	fp = fopen("/proc/mounts", "r");
	if (!fp)
		return -1;

	/*
	 * in order to handle split hierarchy, we need to scan /proc/mounts
	 * and inspect every cgroupfs mount point to find one that has
	 * perf_event subsystem
	 */
	while (fscanf(fp, "%*s %"STR(MAX_PATH)"s %"STR(MAX_PATH)"s %"
				STR(MAX_PATH)"s %*d %*d\n",
				mountpoint, type, tokens) == 3) {

		if (!strcmp(type, "cgroup")) {

			token = strtok_r(tokens, ",", &saved_ptr);

			while (token != NULL) {
				if (!strcmp(token, "perf_event")) {
					found = 1;
					break;
				}
				token = strtok_r(NULL, ",", &saved_ptr);
			}
		}
		if (found)
			break;
	}
	fclose(fp);
	if (!found)
		return -1;

	if (strlen(mountpoint) < maxlen) {
		strcpy(buf, mountpoint);
		return 0;
	}
	return -1;
}

int
open_cgroup(char *name)
{
        char path[MAX_PATH+1];
        char mnt[MAX_PATH+1];
        int cfd = -1;
	int retlen;

        if (cgroupfs_find_mountpoint(mnt, MAX_PATH+1))
                errx(1, "cannot find cgroup fs mount point");

	retlen = snprintf(path, MAX_PATH, "%s/%s", mnt, name);

	/* ensure generated d2path string is valid */
	if (retlen <= 0 || MAX_PATH <= retlen) {
		warn("Unable to generate path name %s/%s\n", mnt, name);
		return cfd;
	}

        cfd = open(path, O_RDONLY);
        if (cfd == -1)
                warn("no access to cgroup %s\n", name);

        return cfd;
}

static void handler(int n)
{
	longjmp(jbuf, 1);
}

int
mainloop(char **arg)
{
	static uint64_t ovfl_count = 0; /* static to avoid setjmp issue */
	struct pollfd pollfds[1];
	int ret;
	int fd = -1;
	int i;

	if (pfm_initialize() != PFM_SUCCESS)
		errx(1, "libpfm initialization failed\n");

	pgsz = sysconf(_SC_PAGESIZE);
	map_size = (options.mmap_pages+1)*pgsz;

	if (options.cgroup) {
		fd = open_cgroup(options.cgroup);
		if (fd == -1)
			err(1, "cannot open cgroup file %s\n", options.cgroup);
	}

	setup_cpu(options.cpu, fd);

	/* done with cgroup */
	if (fd != -1)
		close(fd);

	signal(SIGALRM, handler);
	signal(SIGINT, handler);

	pollfds[0].fd = fds[0].fd;
	pollfds[0].events = POLLIN;

	printf("monitoring on CPU%d, session ending in %ds\n", options.cpu, options.delay);

	if (setjmp(jbuf) == 1)
		goto terminate_session;

	start_cpu();

	alarm(options.delay);
	/*
	 * core loop
	 */
	for(;;) {
		ret = poll(pollfds, 1, -1);
		if (ret < 0 && errno == EINTR)
			break;
		ovfl_count++;
		process_smpl_buf(&fds[0]);
	}
terminate_session:
	for(i=0; i < num_fds; i++)
		close(fds[i].fd);

	/* check for partial event buffer */
	process_smpl_buf(&fds[0]);
	munmap(fds[0].buf, map_size);

	perf_free_fds(fds, num_fds);

	printf("%"PRIu64" samples collected in %"PRIu64" poll events, %"PRIu64" lost samples\n",
		collected_samples,
		ovfl_count, lost_samples);
	return 0;
}

static void
usage(void)
{
	printf("usage: syst_smpl [-h] [-P] [--help] [-m mmap_pages] [-f] [-e event1,...,eventn] [-c cpu] [-d seconds]\n");
}

int
main(int argc, char **argv)
{
	int c;

	setlocale(LC_ALL, "");

	options.cpu = -1;
	options.delay = -1;

	while ((c=getopt_long(argc, argv,"hPe:m:c:d:G:", the_options, 0)) != -1) {
		switch(c) {
			case 0: continue;
			case 'e':
				if (options.events)
					errx(1, "events specified twice\n");
				options.events = optarg;
				break;
			case 'm':
				if (options.mmap_pages)
					errx(1, "mmap pages already set\n");
				options.mmap_pages = atoi(optarg);
				break;
			case 'P':
				options.pin = 1;
				break;
			case 'd':
				options.delay = atoi(optarg);
				break;
			case 'G':
				options.cgroup = optarg;
				break;
			case 'c':
				options.cpu = atoi(optarg);
				break;
			case 'h':
				usage();
				exit(0);
			default:
				errx(1, "unknown option");
		}
	}
	if (!options.events)
		options.events = strdup(gen_events);

	if (!options.mmap_pages)
		options.mmap_pages = 1;
	
	if (options.cpu == -1)
		options.cpu = random() % sysconf(_SC_NPROCESSORS_ONLN);

	if (options.delay == -1)
		options.delay = 10;

	if (options.mmap_pages > 1 && ((options.mmap_pages) & 0x1))
		errx(1, "number of pages must be power of 2\n");

	return mainloop(argv+optind);
}
