/*
 * task_cpu.c - example of per-thread remote monitoring with per-cpu breakdown
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
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <sys/wait.h>
#include <locale.h>
#include <sys/ioctl.h>
#include <err.h>

#include "perf_util.h"

#define MAX_GROUPS	256
#define MAX_CPUS	64

typedef struct {
	const char *events[MAX_GROUPS];
	int num_groups;
	int format_group;
	int inherit;
	int print;
	int pin;
	int ncpus;
	pid_t pid;
} options_t;

static options_t options;
static volatile int quit;

int
child(char **arg)
{
	/*
	 * execute the requested command
	 */
	execvp(arg[0], arg);
	errx(1, "cannot exec: %s\n", arg[0]);
	/* not reached */
}

static void
read_groups(perf_event_desc_t *fds, int num)
{
	uint64_t *values = NULL;
	size_t new_sz, sz = 0;
	int i, evt;
	ssize_t ret;

	/*
	 * 	{ u64		nr;
	 * 	  { u64		time_enabled; } && PERF_FORMAT_ENABLED
	 * 	  { u64		time_running; } && PERF_FORMAT_RUNNING
	 * 	  { u64		value;
	 * 	    { u64	id;           } && PERF_FORMAT_ID
	 * 	  }		cntr[nr];
	 * 	} && PERF_FORMAT_GROUP
	 *
	 * we do not use FORMAT_ID in this program
	 */

	for (evt = 0; evt < num; ) {
		int num_evts_to_read;

		if (options.format_group) {
			num_evts_to_read = perf_get_group_nevents(fds, num, evt);
			new_sz = sizeof(uint64_t) * (3 + num_evts_to_read);
		} else {
			num_evts_to_read = 1;
			new_sz = sizeof(uint64_t) * 3;
		}

		if (new_sz > sz) {
			sz = new_sz;
			values = realloc(values, sz);
		}

		if (!values)
			err(1, "cannot allocate memory for values\n");

		ret = read(fds[evt].fd, values, new_sz);
		if (ret != (ssize_t)new_sz) { /* unsigned */
			if (ret == -1)
				err(1, "cannot read values event %s", fds[evt].name);

			/* likely pinned and could not be loaded */
			warnx("could not read event %d, tried to read %zu bytes, but got %zd",
				evt, new_sz, ret);
		}

		/*
		 * propagate to save area
		 */
		for (i = evt; i < (evt + num_evts_to_read); i++) {
			if (options.format_group)
				values[0] = values[3 + (i - evt)];
			/*
			 * scaling because we may be sharing the PMU and
			 * thus may be multiplexed
			 */
			fds[i].values[0] = values[0];
			fds[i].values[1] = values[1];
			fds[i].values[2] = values[2];
		}
		evt += num_evts_to_read;
	}
	if (values)
		free(values);
}

static void
print_counts(perf_event_desc_t *fds, int num, int cpu)
{
	double ratio;
	uint64_t val, delta;
	int i;

	read_groups(fds, num);

	for(i=0; i < num; i++) {
		val   = perf_scale(fds[i].values);
		delta = perf_scale_delta(fds[i].values, fds[i].prev_values);
		ratio = perf_scale_ratio(fds[i].values);

		/* separate groups */
		if (perf_is_group_leader(fds, i))
			putchar('\n');

		if (options.print)
			printf("CPU%-2d %'20"PRIu64" %'20"PRIu64" %s (%.2f%% scaling, ena=%'"PRIu64", run=%'"PRIu64")\n",
				cpu,
				val,
				delta,
				fds[i].name,
				(1.0-ratio)*100.0,
				fds[i].values[1],
				fds[i].values[2]);
		else
			printf("CPU%-2d %'20"PRIu64" %s (%.2f%% scaling, ena=%'"PRIu64", run=%'"PRIu64")\n",
				cpu,
				val,
				fds[i].name,
				(1.0-ratio)*100.0,
				fds[i].values[1],
				fds[i].values[2]);
	}
}

static void sig_handler(int n)
{
	quit = 1;
}

int
parent(char **arg)
{
	perf_event_desc_t *fds, *fds_cpus[MAX_CPUS];
	int status, ret, i, num_fds = 0, grp, group_fd;
	int ready[2], go[2], cpu;
	char buf;
	pid_t pid;

	go[0] = go[1] = -1;

	if (pfm_initialize() != PFM_SUCCESS)
		errx(1, "libpfm initialization failed");

	if (options.ncpus >= MAX_CPUS)
		errx(1, "maximum number of cpus exceeded (%d)", MAX_CPUS);

	memset(fds_cpus, 0, sizeof(fds_cpus));

	for (cpu=0; cpu < options.ncpus; cpu++) {
		for (grp = 0; grp < options.num_groups; grp++) {
			num_fds = 0;
			ret = perf_setup_list_events(options.events[grp], &fds_cpus[cpu], &num_fds);
			if (ret || !num_fds)
				exit(1);
		}
	}

	pid = options.pid;
	if (!pid) {
		ret = pipe(ready);
		if (ret)
			err(1, "cannot create pipe ready");

		ret = pipe(go);
		if (ret)
			err(1, "cannot create pipe go");


		/*
		 * Create the child task
		 */
		if ((pid=fork()) == -1)
			err(1, "Cannot fork process");

		/*
		 * and launch the child code
		 *
		 * The pipe is used to avoid a race condition
		 * between for() and exec(). We need the pid
		 * of the new tak but we want to start measuring
		 * at the first user level instruction. Thus we
		 * need to prevent exec until we have attached
		 * the events.
		 */
		if (pid == 0) {
			close(ready[0]);
			close(go[1]);

			/*
			 * let the parent know we exist
			 */
			close(ready[1]);
			if (read(go[0], &buf, 1) == -1)
				err(1, "unable to read go_pipe");


			exit(child(arg));
		}

		close(ready[1]);
		close(go[0]);

		if (read(ready[0], &buf, 1) == -1)
			err(1, "unable to read child_ready_pipe");

		close(ready[0]);
	}

	for (cpu=0; cpu < options.ncpus; cpu++) {
		fds = fds_cpus[cpu];
		for(i=0; i < num_fds; i++) {
			int is_group_leader; /* boolean */

			is_group_leader = perf_is_group_leader(fds, i);
			if (is_group_leader) {
				/* this is the group leader */
				group_fd = -1;
			} else {
				group_fd = fds[fds[i].group_leader].fd;
			}

			/*
			 * create leader disabled with enable_on-exec
			 */
			if (!options.pid) {
				fds[i].hw.disabled = is_group_leader;
				fds[i].hw.enable_on_exec = is_group_leader;
			}

			fds[i].hw.read_format = PERF_FORMAT_SCALE;
			/* request timing information necessary for scaling counts */
			if (is_group_leader && options.format_group)
				fds[i].hw.read_format |= PERF_FORMAT_GROUP;

			if (options.inherit)
				fds[i].hw.inherit = 1;

			if (options.pin && is_group_leader)
				fds[i].hw.pinned = 1;
			fds[i].fd = perf_event_open(&fds[i].hw, pid, cpu, group_fd, 0);
			if (fds[i].fd == -1) {
				warn("cannot attach event%d %s", i, fds[i].name);
				goto error;
			}
		}
	}

	if (!options.pid && go[1] > -1)
		close(go[1]);

	if (options.print) {
		if (!options.pid) {
			while(waitpid(pid, &status, WNOHANG) == 0) {
				sleep(1);
				for (cpu=0; cpu < options.ncpus; cpu++) {
					fds = fds_cpus[cpu];
					print_counts(fds, num_fds, cpu);
				}
			}
		} else {
			while(quit == 0) {
				sleep(1);
				for (cpu=0; cpu < options.ncpus; cpu++) {
					fds = fds_cpus[cpu];
					print_counts(fds, num_fds, cpu);
				}
			}
		}
	} else {
		if (!options.pid)
			waitpid(pid, &status, 0);
		else {
			pause();
 			for (cpu=0; cpu < options.ncpus; cpu++) {
 				fds = fds_cpus[cpu];
 				for(i=0; i < num_fds; i++)
 					ioctl(fds[i].fd, PERF_EVENT_IOC_DISABLE, 0);
 			}
		}
		for (cpu=0; cpu < options.ncpus; cpu++) {
			fds = fds_cpus[cpu];
			print_counts(fds, num_fds, cpu);
		}
	}

	for (cpu=0; cpu < options.ncpus; cpu++) {
		fds = fds_cpus[cpu];
		for(i=0; i < num_fds; i++)
			close(fds[i].fd);
		perf_free_fds(fds, num_fds);
	}

	/* free libpfm resources cleanly */
	pfm_terminate();

	return 0;
error:
	free(fds);
	if (!options.pid)
		kill(SIGKILL, pid);

	/* free libpfm resources cleanly */
	pfm_terminate();

	return -1;
}

static void
usage(void)
{
	printf("usage: task_cpu [-h] [-i] [-g] [-p] [-P] [-t pid] [-e event1,event2,...] cmd\n"
		"-h\t\tget help\n"
		"-i\t\tinherit across fork\n"
		"-f\t\tuse PERF_FORMAT_GROUP for reading up counts (experimental, not working)\n"
		"-p\t\tprint counts every second\n"
		"-P\t\tpin events\n"
		"-t pid\tmeasure existing pid\n"
		"-e ev,ev\tgroup of events to measure (multiple -e switches are allowed)\n"
		);
}

int
main(int argc, char **argv)
{
	int c;

	setlocale(LC_ALL, "");

	while ((c=getopt(argc, argv,"+he:ifpPt:")) != -1) {
		switch(c) {
			case 'e':
				if (options.num_groups < MAX_GROUPS) {
					options.events[options.num_groups++] = optarg;
				} else {
					errx(1, "you cannot specify more than %d groups.\n",
						MAX_GROUPS);
				}
				break;
			case 'f':
				options.format_group = 1;
				break;
			case 'p':
				options.print = 1;
				break;
			case 'P':
				options.pin = 1;
				break;
			case 'i':
				options.inherit = 1;
				break;
			case 't':
				options.pid = atoi(optarg);
				break;
			case 'h':
				usage();
				exit(0);
			default:
				errx(1, "unknown error");
		}
	}
	options.ncpus = sysconf(_SC_NPROCESSORS_ONLN);
	if (options.ncpus < 1)
		errx(1, "cannot determine number of online processors");

	if (options.num_groups == 0) {
		options.events[0] = "cycles:u,instructions:u";
		options.num_groups = 1;
	}
	if (!argv[optind] && !options.pid)
		errx(1, "you must specify a command to execute or a thread to attach to\n");

	signal(SIGINT, sig_handler);

	return parent(argv+optind);
}
