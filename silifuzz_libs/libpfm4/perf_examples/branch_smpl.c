/*
 * branch_smpl.c - example of a branch sampling on another task
 *
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
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <setjmp.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include <sys/mman.h>
#include <locale.h>
#include <sys/ioctl.h>
#include <err.h>

#include "perf_util.h"

#define DFL_BR_EVENT "branches:freq=100:u"

typedef struct {
	int opt_no_show;
	int opt_inherit;
	uint64_t branch_filt;
	int cpu;
	int mmap_pages;
	char *events;
	FILE *output_file;
} options_t;

static jmp_buf jbuf;
static uint64_t collected_samples, lost_samples;
static perf_event_desc_t *fds;
static int num_fds;
static options_t options;

static void
cld_handler(int n)
{
	longjmp(jbuf, 1);
}

int
child(char **arg)
{
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

		if (options.opt_no_show) {
			perf_skip_buffer(hw, ehdr.size - sizeof(ehdr));
			continue;
		}

		switch(ehdr.type) {
			case PERF_RECORD_SAMPLE:
				collected_samples++;
				ret = perf_display_sample(fds, num_fds, hw - fds, &ehdr, options.output_file);
				if (ret)
					errx(1, "cannot parse sample");
				break;
			case PERF_RECORD_EXIT:
				display_exit(hw, options.output_file);
				break;
			case PERF_RECORD_LOST:
				lost_samples += display_lost(hw, fds, num_fds, options.output_file);
				break;
			case PERF_RECORD_THROTTLE:
				display_freq(1, hw, options.output_file);
				break;
			case PERF_RECORD_UNTHROTTLE:
				display_freq(0, hw, options.output_file);
				break;
			default:
				printf("unknown sample type %d\n", ehdr.type);
				perf_skip_buffer(hw, ehdr.size - sizeof(ehdr));
		}
	}
}

int
mainloop(char **arg)
{
	static uint64_t ovfl_count; /* static to avoid setjmp issue */
	struct pollfd pollfds[1];
	sigset_t bmask;
	int go[2], ready[2];
	size_t pgsz;
	size_t map_size = 0;
	pid_t pid;
	int status, ret;
	int i;
	char buf;

	if (pfm_initialize() != PFM_SUCCESS)
		errx(1, "libpfm initialization failed\n");

	pgsz = sysconf(_SC_PAGESIZE);
	map_size = (options.mmap_pages+1)*pgsz;

	/*
	 * does allocate fds
	 */
	ret  = perf_setup_list_events(options.events, &fds, &num_fds);
	if (ret || !num_fds)
		errx(1, "cannot setup event list");

	memset(pollfds, 0, sizeof(pollfds));

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
		err(1, "cannot fork process\n");

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

	fds[0].fd = -1;

	if (!fds[0].hw.sample_period)
		errx(1, "need to set sampling period or freq on first event, use :period= or :freq=");

	for(i=0; i < num_fds; i++) {

		if (i == 0) {
			fds[i].hw.disabled = 1;
			fds[i].hw.enable_on_exec = 1; /* start immediately */
		} else
			fds[i].hw.disabled = 0;


		if (options.opt_inherit)
			fds[i].hw.inherit = 1;

		if (fds[i].hw.sample_period) {
			/*
			 * set notification threshold to be halfway through the buffer
			 */
			fds[i].hw.wakeup_watermark = (options.mmap_pages*pgsz) / 2;
			fds[i].hw.watermark = 1;

			fds[i].hw.sample_type = PERF_SAMPLE_IP|PERF_SAMPLE_TID|PERF_SAMPLE_READ|PERF_SAMPLE_TIME|PERF_SAMPLE_PERIOD;
			/*
			 * if we have more than one event, then record event identifier to help with parsing
			 */
			if (num_fds > 1)
				fds[i].hw.sample_type |= PERF_SAMPLE_IDENTIFIER;

			fprintf(options.output_file,"%s period=%"PRIu64" freq=%d\n", fds[i].name, fds[i].hw.sample_period, fds[i].hw.freq);

			fds[i].hw.read_format = PERF_FORMAT_SCALE;

			if (fds[i].hw.freq)
				fds[i].hw.sample_type |= PERF_SAMPLE_PERIOD;

			fds[i].hw.sample_type = PERF_SAMPLE_BRANCH_STACK;
			fds[i].hw.branch_sample_type = options.branch_filt;
		}
		/*
		 * we are grouping the events, so there may be a limit
		 */
		fds[i].fd = perf_event_open(&fds[i].hw, pid, options.cpu, fds[0].fd, 0);
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

	if (num_fds > 1 && fds[0].fd > -1) {
		for(i = 0; i < num_fds; i++) {
			/*
			 * read the event identifier using ioctl
			 * new method replaced the trick with PERF_FORMAT_GROUP + PERF_FORMAT_ID + read()
			 */
			ret = ioctl(fds[i].fd, PERF_EVENT_IOC_ID, &fds[i].id);
			if (ret == -1)
				err(1, "cannot read ID");
			fprintf(options.output_file,"ID %"PRIu64"  %s\n", fds[i].id, fds[i].name);
		}
	}

	pollfds[0].fd = fds[0].fd;
	pollfds[0].events = POLLIN;
	
	for(i=0; i < num_fds; i++) {
		ret = ioctl(fds[i].fd, PERF_EVENT_IOC_ENABLE, 0);
		if (ret)
			err(1, "cannot enable event %s\n", fds[i].name);
	}
	signal(SIGCHLD, cld_handler);

	close(go[1]);

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

	for(i=0; i < num_fds; i++)
		close(fds[i].fd);

	/* check for partial event buffer */
	process_smpl_buf(&fds[0]);
	munmap(fds[0].buf, map_size);

	perf_free_fds(fds, num_fds);

	fprintf(options.output_file,
		"%"PRIu64" samples collected in %"PRIu64" poll events, %"PRIu64" lost samples\n",
		collected_samples,
		ovfl_count, lost_samples);

	/* free libpfm resources cleanly */
	pfm_terminate();

	fclose(options.output_file);

	return 0;
}

typedef struct {
	const char *filt;
	const int flag;
} branch_filt_t;

#define FILT(a, b) { .filt = a, .flag = b }

static const branch_filt_t br_filters[] = {
	/* priv level filters */
	FILT("u", PERF_SAMPLE_BRANCH_USER),
	FILT("k", PERF_SAMPLE_BRANCH_KERNEL),
	FILT("hv", PERF_SAMPLE_BRANCH_HV),

	FILT("any", PERF_SAMPLE_BRANCH_ANY),
	FILT("call", PERF_SAMPLE_BRANCH_ANY_CALL),
	FILT("return", PERF_SAMPLE_BRANCH_ANY_RETURN),
	FILT("indirect", PERF_SAMPLE_BRANCH_IND_CALL),
	FILT("conditional", PERF_SAMPLE_BRANCH_COND),
	FILT("indirect_jump", PERF_SAMPLE_BRANCH_IND_JUMP),
	FILT(NULL, 0),
};

static void parse_branch_arg(const char *arg)
{
	const branch_filt_t *br;
	char *q, *p, *str;

	if (!arg) {
		options.branch_filt = PERF_SAMPLE_BRANCH_ANY;
		return;
	}

	str = q = strdup(arg);
	if (!str)
		err(1, "cannot allocate memory to dup string");

	while (*q) {
		p = strchr(q, ',');
		if (p)
			*p = '\0';

		for (br = br_filters; br->filt; br++) {
			if (!strcasecmp(q, br->filt))
				options.branch_filt |= br->flag;
		}
		if (!br->filt)
			errx(1, "unknown branch filter %s", q);
		if (!p)
			break;
		str = p + 1;
	}
	free(str);

#define BR_PLM (PERF_SAMPLE_BRANCH_USER|PERF_SAMPLE_BRANCH_KERNEL|PERF_SAMPLE_BRANCH_HV)

	if (!(options.branch_filt & ~BR_PLM))
		errx(1, "no branch mode specified, privilege level does not define a branch type, use the any filter");
}

static void
usage(void)
{
	printf("usage: branch_smpl [-h] [--help] [-i] [-c cpu] [-m mmap_pages] [-b] [-j br-filt] [-o output_file] [-e event1] cmd\n"
	      "\t-j br-filt\t : comma separated list of branch filters among: u, k, any, call, returrn, indirect, conditional, indirect_jmp\n"
	      "\t-b\t\t : sample any branch (equivalent to -j any), default mode\n");
}

int
main(int argc, char **argv)
{
	int c;

	setlocale(LC_ALL, "");

	options.cpu = -1;
	options.output_file = stdout;

	while ((c=getopt(argc, argv,"he:m:ic:o:j:b")) != -1) {
		switch(c) {
			case 0: continue;
			case 'e':
				if (options.events)
					errx(1, "events specified twice\n");
				options.events = optarg;
				break;
			case 'i':
				options.opt_inherit = 1;
				break;
			case 'm':
				if (options.mmap_pages)
					errx(1, "mmap pages already set\n");
				options.mmap_pages = atoi(optarg);
				break;
			case 'b':
				if (options.branch_filt)
					errx(1, "cannot use multiple branch filter options");
				options.branch_filt = PERF_SAMPLE_BRANCH_ANY;
				break;
			case 'j':
				if (options.branch_filt)
					errx(1, "cannot set multiple branch options");
				parse_branch_arg(optarg);
				break;
			case 'c':
				options.cpu = atoi(optarg);
				break;
			case 'o':
				options.output_file = fopen(optarg,"w");
				if (!options.output_file)
					err(1, "cannot create file %s\n", optarg);
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

	if (!options.branch_filt)
		options.branch_filt = PERF_SAMPLE_BRANCH_ANY | PERF_SAMPLE_BRANCH_USER;

	/*
	 * use low frequency rate to avoid flooding output
	 * use generic branches event to make this test more portable
	 */
	if (!options.events)
		options.events = strdup(DFL_BR_EVENT);

	if (!options.mmap_pages)
		options.mmap_pages = 1;
	
	if (options.mmap_pages > 1 && ((options.mmap_pages) & 0x1))
		errx(1, "number of pages must be power of 2 greater than 1\n");

	printf("branch_filt=0x%"PRIx64"\n", options.branch_filt);
	printf("event=%s\n", options.events);
	return mainloop(argv+optind);
}
