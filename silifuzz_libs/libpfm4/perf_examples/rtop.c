/* rtop.c - a simple PMU-based CPU utilization tool
 *
 * Copyright (c) 2009 Google, Inc
 * Contributed by Stephane Eranian <eranian@gmail.com>
 *
 * Based on:
 * Copyright (c) 2004-2006 Hewlett-Packard Development Company, L.P.
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
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <curses.h>
#include <termios.h>
#include <signal.h>
#include <ctype.h>
#include <math.h>
#include <limits.h>
#include <err.h>

#include "perf_util.h"

#define RTOP_VERSION "0.2"
/* 
 * max number of cpus (threads) supported
 */
#define RTOP_MAX_CPUS		2048 /* MUST BE power of 2 */
#define RTOP_CPUMASK_BITS	(sizeof(unsigned long)<<3)
#define RTOP_CPUMASK_COUNT	(RTOP_MAX_CPUS/RTOP_CPUMASK_BITS)

#define RTOP_CPUMASK_SET(m, g)		((m)[(g)/RTOP_CPUMASK_BITS] |=  (1UL << ((g) % RTOP_CPUMASK_BITS)))
#define RTOP_CPUMASK_CLEAR(m, g)	((m)[(g)/RTOP_CPUMASK_BITS] &= ~(1UL << ((g) % RTOP_CPUMASK_BITS)))
#define RTOP_CPUMASK_ISSET(m, g)	((m)[(g)/RTOP_CPUMASK_BITS] &   (1UL << ((g) % RTOP_CPUMASK_BITS)))

typedef unsigned long rtop_cpumask_t[RTOP_CPUMASK_COUNT];

typedef struct {
	struct {
		int	opt_verbose;
		int	opt_delay;	/* refresh delay in second */
		int	opt_delay_set;
	} program_opt_flags;
	rtop_cpumask_t	cpu_mask;	  /* which CPUs to use in system wide mode */
	int		online_cpus;
	int		selected_cpus;
	unsigned long	cpu_mhz;
} program_options_t;

#define opt_verbose program_opt_flags.opt_verbose
#define opt_delay program_opt_flags.opt_delay
#define opt_delay_set program_opt_flags.opt_delay_set


static program_options_t 	options;
static struct termios		saved_tty;
static int			time_to_quit;
static int			term_rows, term_cols;

static void
get_term_size(void)
{
	int ret;
        struct winsize ws;

	ret = ioctl(1, TIOCGWINSZ, &ws);
	if (ret) 
		err(1, "cannot determine screen size");

	if (ws.ws_row > 10) {
                term_cols = ws.ws_col;
                term_rows = ws.ws_row;
        } else {
                term_cols = 80;
                term_rows = 24;
        }

	if (term_rows < options.selected_cpus)
		errx(1, "you need at least %d rows on your terminal to display all CPUs", options.selected_cpus);
}

static void
sigwinch_handler(int n)
{
	get_term_size();
}

static void
setup_screen(void)
{
	int ret;

	ret = tcgetattr(0, &saved_tty);
	if (ret == -1)
		errx(1, "cannot save tty settings\n");

	get_term_size();

	initscr();
	nocbreak();
	resizeterm(term_rows, term_cols);
}

static void
close_screen(void)
{
	endwin();

	tcsetattr(0, TCSAFLUSH, &saved_tty);
}

static void
fatal_errorw(char *fmt, ...)
{
	va_list ap;

	close_screen();

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	exit(1);
}

static void
sigint_handler(int n)
{
	time_to_quit = 1;
}

static unsigned long
find_cpu_speed(void)
{
	FILE *fp1;	
	unsigned long f1 = 0, f2 = 0;
	char buffer[128], *p, *value;

	memset(buffer, 0, sizeof(buffer));

	fp1 = fopen("/proc/cpuinfo", "r");
	if (fp1 == NULL)
		return 0;

	for (;;) {
		buffer[0] = '\0';

		p  = fgets(buffer, 127, fp1);
		if (p == NULL)
			break;

		/* skip  blank lines */
		if (*p == '\n') continue;

		p = strchr(buffer, ':');
		if (p == NULL)
			break;

		/*
		 * p+2: +1 = space, +2= firt character
		 * strlen()-1 gets rid of \n
		 */
		*p = '\0';
		value = p+2;

		value[strlen(value)-1] = '\0';

		if (!strncasecmp("cpu MHz", buffer, 7)) {
			float fl;
			sscanf(value, "%f", &fl);
			f1 = lroundf(fl);
			break;
		}
		if (!strncasecmp("BogoMIPS", buffer, 8)) {
			float fl;
			sscanf(value, "%f", &fl);
			f2 = lroundf(fl);
		}
	}
	fclose(fp1);
	return f1 == 0 ? f2 : f1;
}

static void
setup_signals(void)
{
	struct sigaction act;
	sigset_t my_set;

	/*
	 * SIGINT is a asynchronous signal
	 * sent to the process (not a specific thread). POSIX states
	 * that one and only one thread will execute the handler. This
	 * could be any thread that does not have the signal blocked.
	 */

	/*
	 * install SIGINT handler
	 */
	memset(&act,0,sizeof(act));
	sigemptyset(&my_set);
	act.sa_handler = sigint_handler;
	sigaction (SIGINT, &act, 0);

	/*
	 * install SIGWINCH handler
	 */
	memset(&act,0,sizeof(act));
	sigemptyset(&my_set);
	act.sa_handler = sigwinch_handler;
	sigaction (SIGWINCH, &act, 0);
}

static struct option rtop_cmd_options[]={
	{ "help", 0, 0, 1 },
	{ "version", 0, 0, 2 },
	{ "delay", 0, 0, 3 },
	{ "cpu-list", 1, 0, 4 },

	{ "verbose", 0, &options.opt_verbose, 1 },
	{ 0, 0, 0, 0}
};

#define MAX_EVENTS	2

typedef struct {
	uint64_t prev_values[MAX_EVENTS];
	int fd[MAX_EVENTS];
	int cpu;
} cpudesc_t;

/*
 * 	{ u64		nr;
 * 	  { u64		time_enabled; } && PERF_FORMAT_ENABLED
 * 	  { u64		time_running; } && PERF_FORMAT_RUNNING
 * 	  { u64		value;
 * 	    { u64	id;           } && PERF_FORMAT_ID
 * 	  }		cntr[nr];
 */
typedef struct {
	uint64_t nr;
	uint64_t time_enabled;
	uint64_t time_running;
	uint64_t values[2];
} rtop_grp_t;

static void
mainloop(void)
{
	struct perf_event_attr ev[MAX_EVENTS];
	unsigned long itc_delta;
	cpudesc_t *cpus;
	int i, j = 0, k, ncpus = 0;
	int num, ret;

	ncpus = options.selected_cpus;

	cpus = calloc(ncpus, sizeof(cpudesc_t));
	if (!cpus)
		err(1, "cannot allocate file descriptors");

	memset(ev, 0, sizeof(ev));

	/* measure user cycles */
	ev[0].type = PERF_TYPE_HARDWARE;
	ev[0].config = PERF_COUNT_HW_CPU_CYCLES;
	ev[0].read_format = PERF_FORMAT_SCALE|PERF_FORMAT_GROUP;
	ev[0].exclude_kernel = 1;
	ev[0].disabled = 1;
	ev[0].pinned = 0;

	/* measure kernel cycles */
	ev[1].type = PERF_TYPE_HARDWARE;
	ev[1].config = PERF_COUNT_HW_CPU_CYCLES;
	ev[1].exclude_user = 1;
	ev[1].disabled = 1;
	ev[1].pinned = 0;

	num = 2;

	for(i=0, k = 0; ncpus; i++) {
		if (RTOP_CPUMASK_ISSET(options.cpu_mask, i) == 0)
			continue;

		cpus[k].cpu = i;
		cpus[k].fd[0] = -1;
		for(j=0 ; j < num; j++) {
			cpus[k].fd[j] = perf_event_open(ev+j, -1, i, cpus[k].fd[0], 0);
			if (cpus[k].fd[j] == -1)
				fatal_errorw("cannot open event %d on CPU%d: %s\n", j, i, strerror(errno));
		}
		ncpus--;
		k++;
	}
	ncpus = options.selected_cpus;

	itc_delta = options.opt_delay * options.cpu_mhz * 1000000;

	for(i=0; i < ncpus; i++)
		for(j=0; j < num; j++)
			ioctl(cpus[i].fd[j], PERF_EVENT_IOC_ENABLE, 0);
	
	for(;time_to_quit == 0;) {

		sleep(options.opt_delay);

		move(0, 0);

		for(i=0; i < ncpus; i++) {
			uint64_t values[MAX_EVENTS];
			uint64_t raw_values[5];
			double k_cycles, u_cycles, i_cycles, ratio;

			/*
			 * given our events are in the same group, we can do a
			 * group read and get both counts + scaling information
			 */
			ret = read(cpus[i].fd[0], raw_values, sizeof(raw_values));
			if (ret != sizeof(raw_values))
				fatal_errorw("cannot read count for event %d on CPU%d\n", j, cpus[i].cpu);

			if (options.opt_verbose) {
				printw("nr=%"PRIu64"\n", raw_values[0]);
				printw("ena=%"PRIu64"\n", raw_values[1]);
				printw("run=%"PRIu64"\n", raw_values[2]);
			}

			raw_values[0] = raw_values[3];
			values[0] = perf_scale(raw_values);

			raw_values[0] = raw_values[4];
			values[1] = perf_scale(raw_values);

			ratio = perf_scale_ratio(raw_values);

			k_cycles   = (double)(values[1] - cpus[i].prev_values[1])*100.0/ (double)itc_delta;
			u_cycles   = (double)(values[0] - cpus[i].prev_values[0])*100.0/ (double)itc_delta;
			i_cycles   = 100.0 - (k_cycles + u_cycles);

			cpus[i].prev_values[0] = values[0];
			cpus[i].prev_values[1] = values[1];
			/*
			 * adjust for rounding errors
			 */
			if (i_cycles < 0.0) i_cycles = 0.0;
			if (i_cycles > 100.0) i_cycles = 100.0;
			if (k_cycles > 100.0) k_cycles = 100.0;
			if (u_cycles > 100.0) u_cycles = 100.0;

			printw("CPU%-2ld %6.2f%% usr %6.2f%% sys %6.2f%% idle (scaling ratio %.2f%%)\n",
				i,
				u_cycles,
				k_cycles,
				i_cycles,
				ratio*100.0);
		}
		refresh();


	}
	for(i=0; i < ncpus; i++)
		for(j=0; j < num; j++)
			close(cpus[i].fd[j]);
	free(cpus);
}

void
populate_cpumask(char *cpu_list)
{
	char *p;
	int start_cpu, end_cpu = 0;
	int i, count = 0;

	options.online_cpus = (int)sysconf(_SC_NPROCESSORS_ONLN);
	if (options.online_cpus == -1) 
		errx(1, "cannot figure out the number of online processors");

	if (cpu_list == NULL)  {
		if (options.online_cpus >= RTOP_MAX_CPUS)
			errx(1, "rtop can only handle to %u CPUs", RTOP_MAX_CPUS);

		for(i=0; i < options.online_cpus; i++)
			RTOP_CPUMASK_SET(options.cpu_mask, i);

		options.selected_cpus = options.online_cpus;

		return;
	} 

	while(isdigit(*cpu_list)) { 
		p = NULL;
		start_cpu = strtoul(cpu_list, &p, 0); /* auto-detect base */

		if (start_cpu == INT_MAX || (*p != '\0' && *p != ',' && *p != '-'))
			goto invalid;

		if (p && *p == '-') {
			cpu_list = ++p;
			p = NULL;

			end_cpu = strtoul(cpu_list, &p, 0); /* auto-detect base */
			
			if (end_cpu == INT_MAX || (*p != '\0' && *p != ','))
				goto invalid;
			if (end_cpu < start_cpu)
				goto invalid_range; 
		} else {
			end_cpu = start_cpu;
		}

		if (start_cpu >= RTOP_MAX_CPUS || end_cpu >= RTOP_MAX_CPUS)
			goto too_big;

		for (; start_cpu <= end_cpu; start_cpu++) {

			if (start_cpu >= options.online_cpus)
				goto not_online; /* XXX: assume contiguous range of CPUs */

			if (RTOP_CPUMASK_ISSET(options.cpu_mask, start_cpu))
				continue;

			RTOP_CPUMASK_SET(options.cpu_mask, start_cpu);

			count++;
		}

		if (*p) ++p;

		cpu_list = p;
	}

	options.selected_cpus = count;

	return;
invalid:
	errx(1, "invalid cpu list argument: %s", cpu_list);
	/* no return */
not_online:
	errx(1, "cpu %d is not online", start_cpu);
	/* no return */
invalid_range:
	errx(1, "cpu range %d - %d is invalid", start_cpu, end_cpu);
	/* no return */
too_big:
	errx(1, "rtop is limited to %d CPUs", RTOP_MAX_CPUS);
	/* no return */
}


static void
usage(void)
{
	printf(	"usage: rtop [options]:\n"
		"-h, --help\t\t\tdisplay this help and exit\n"
		"-v, --verbose\t\t\tverbose output\n"
		"-V, --version\t\t\tshow version and exit\n"
		"-d nsec, --delay=nsec\t\tnumber of seconds between refresh (default=1s)\n"
		"--cpu-list=cpu1,cpu2\t\tlist of CPUs to monitor(default=all)\n"
	);

}

int
main(int argc, char **argv)
{
	int c;
	char *cpu_list = NULL;

	//if (geteuid()) err(1, "perf_event requires root privileges to create system-wide measurments\n");

	while ((c=getopt_long(argc, argv,"+vhVd:", rtop_cmd_options, 0)) != -1) {
		switch(c) {
			case   0: continue; /* fast path for options */
			case 'v': options.opt_verbose++;
				  break;
			case 1:
			case 'h':
				usage();
				exit(0);
			case 2:
			case 'V':
				printf("rtop version " RTOP_VERSION " Date: " __DATE__ "\n"
					"Copyright (C) 2009 Google, Inc\n");
				exit(0);
			case 3:
			case 'd':
				options.opt_delay = atoi(optarg);
				if (options.opt_delay < 0)
					errx(1, "invalid delay, must be >= 0");
				options.opt_delay_set = 1;
				break;
			case 4:
				if (*optarg == '\0')
					errx(1, "--cpu-list needs an argument\n");
				cpu_list = optarg;
				break;
			default:
				errx(1, "unknown option\n");
		}
	}
	/*
	 * default refresh delay
	 */
	if (options.opt_delay_set == 0)
		options.opt_delay = 1;

	options.cpu_mhz = find_cpu_speed();

	populate_cpumask(cpu_list);

	setup_signals();
	setup_screen();
	mainloop();
	close_screen();

	return 0;
}
