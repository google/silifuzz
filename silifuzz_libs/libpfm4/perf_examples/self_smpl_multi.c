/*
 *
 * self_smpl_multi.c - multi-thread self-sampling program
 *
 * Copyright (c) 2009  Google, Inc
 * Modified by Stephane Eranian <eranian@gmail.com>
 *
 * Based on:
 * Copyright (c) 2008 Mark W. Krentel
 * Contributed by Mark W. Krentel <krentel@cs.rice.edu>
 * Modified by Stephane Eranian <eranian@gmail.com>
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
 *
 *  Test perfmon overflow without PAPI.
 *
 *  Create a new thread, launch perfmon overflow counters in both
 *  threads, print the number of interrupts per thread and per second,
 *  and look for anomalous interrupts.  Look for mismatched thread
 *  ids, bad message type, or failed pfm_restart().
 *
 *  self_smpl_multi is a test program to stress signal delivery in the context
 *  of a multi-threaded self-sampling program which is common with PAPI and HPC.
 * 
 *  There is an issue with existing (as of 2.6.30) kernel which do not provide
 *  a reliable way of having the signal delivered to the thread in which the
 *  counter overflow occurred. This is problematic for many self-monitoring
 *  program.
 *
 *  This program demonstrates the issue by tracking the number of times
 *  the signal goes to the wrong thread. The bad behavior is exacerbated
 *  if the monitored threads, themselves, already use signals. Here we
 *  use SIGLARM.
 *
 *  Note that kernel developers have been made aware of this problem and
 *  a fix has been proposed. It introduces a new F_SETOWN_EX command to
 *  fcntl().
 */
#include <sys/time.h>
#include <sys/types.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "perf_util.h"

#define PROGRAM_TIME  8
#define THRESHOLD  20000000

static int program_time = PROGRAM_TIME;
static int threshold = THRESHOLD;
static int signum = SIGIO;
static pthread_barrier_t barrier;


static int buffer_pages = 1;

#define MAX_THR  128

/*
 *  the following definitions come
 *  from the F_SETOWN_EX patch from Peter Zijlstra
 * Check out: http://lkml.org/lkml/2009/8/4/128 
 */
#ifndef F_SETOWN_EX
#define F_SETOWN_EX	15
#define F_GETOWN_EX	16

#define F_OWNER_TID	0
#define F_OWNER_PID	1
#define F_OWNER_PGRP	2

struct f_owner_ex {
	int	type;
	pid_t	pid;
};
#endif

struct over_args {
	int fd;
	pid_t tid;
	int id;
	perf_event_desc_t *fds;
};

struct over_args fd2ov[MAX_THR];

long count[MAX_THR];
long total[MAX_THR];
long iter[MAX_THR];
long mismatch[MAX_THR];
long bad_msg[MAX_THR];
long bad_restart[MAX_THR];
int fown;

static __thread int myid; /* TLS */
static __thread perf_event_desc_t *fds; /* TLS */
static __thread int num_fds; /* TLS */

pid_t
gettid(void)
{
	return (pid_t)syscall(__NR_gettid);
}

void
user_callback(int m)
{
	count[m]++;
	total[m]++;
}

void
do_cycles(void)
{
	struct timeval start, last, now;
	unsigned long x, sum;

	gettimeofday(&start, NULL);
	last = start;
	count[myid] = 0;
	total[myid] = 0;
	iter[myid] = 0;

	do {

		sum = 1;
		for (x = 1; x < 250000; x++) {
			/* signal pending to private queue because of
			 * pthread_kill(), i.e., tkill()
			 */
			if ((x % 5000) == 0)
				pthread_kill(pthread_self(), SIGUSR1);
			sum += x;
		}
		iter[myid]++;

		gettimeofday(&now, NULL);
		if (now.tv_sec > last.tv_sec) {
			printf("%ld: myid = %3d, fd = %3d, count = %4ld, iter = %4ld, rate = %ld/Kiter\n",
				(long)(now.tv_sec - start.tv_sec),
				myid,
				fd2ov[myid].fd,
				count[myid], iter[myid],
				(1000 * count[myid])/iter[myid]);

			count[myid] = 0;
			iter[myid] = 0;
			last = now;
		}
	} while (now.tv_sec < start.tv_sec + program_time);
}

#define DPRINT(str)   \
printf("(%s) si->fd = %d, ov->self = 0x%lx, self = 0x%lx\n",   \
       str, fd, (unsigned long)ov->self, (unsigned long)self)
void
sigusr1_handler(int sig, siginfo_t *info, void *context)
{
}

/*
 * a signal handler cannot safely invoke printf()
 */
void
sigio_handler(int sig, siginfo_t *info, void *context)
{
	perf_event_desc_t *fdx;
	struct perf_event_header ehdr;
	struct over_args *ov;
	int fd, i, ret;
	pid_t tid;

	/*
	 * positive si_code indicate kernel generated signal
	 * which is normal for SIGIO
	 */
	if (info->si_code < 0)
		errx(1, "signal not generated by kernel");

	/*
	 * SIGPOLL = SIGIO
	 * expect POLL_HUP instead of POLL_IN because we are
	 * in one-shot mode (IOC_REFRESH)
	 */
	if (info->si_code != POLL_HUP)
		errx(1, "signal not generated by SIGIO: %d", info->si_code);

	fd = info->si_fd;
 	tid = gettid();

	for(i=0; i < MAX_THR; i++)
		if (fd2ov[i].fd == fd)
			break;

	if (i == MAX_THR)
		errx(1, "bad info.si_fd: %d", fd);

 	ov = &fd2ov[i];

	/*
 	 * current thread id may not always match the id
 	 * associated with the file descriptor
 	 *
 	 * We need to use the other's thread fds info
 	 * otherwise, it is going to get stuck with no
 	 * more samples generated
 	 */
	if (tid != ov->tid) {
		mismatch[myid]++;
		fdx = ov->fds;
	} else {
		fdx = fds;
	}

	/*
 	 * read sample header
 	 */
	ret = perf_read_buffer(fdx+0, &ehdr, sizeof(ehdr));
	if (ret) {
		errx(1, "cannot read event header");
	}

	/*
	 * message we do not handle
	 */
	if (ehdr.type != PERF_RECORD_SAMPLE) {
		bad_msg[myid]++;
		goto skip;
	}
	user_callback(myid);
skip:
	/* mark sample as consumed */
	perf_skip_buffer(fdx+0, ehdr.size);

	/*
	 * re-arm period, next notification after wakeup_events
	 */
	ret = ioctl(fd, PERF_EVENT_IOC_REFRESH, 1);
	if (ret)
		err(1, "cannot refresh");
}

void
overflow_start(char *name)
{
	struct f_owner_ex fown_ex;
	struct over_args *ov;
	size_t pgsz;
	int ret, fd, flags;

	fds = NULL;
	num_fds = 0;
	ret = perf_setup_list_events("cycles:u", &fds, &num_fds);
	if (ret || !num_fds)
		errx(1, "cannot monitor event");

	pgsz = sysconf(_SC_PAGESIZE);
	ov = &fd2ov[myid];

	/* do not enable now */
	fds[0].hw.disabled = 1;

	/* notify after 1 sample */
	fds[0].hw.wakeup_events = 1;
	fds[0].hw.sample_type = PERF_SAMPLE_IP;
	fds[0].hw.sample_period = threshold;
	fds[0].hw.read_format = 0;

	fds[0].fd = fd = perf_event_open(&fds[0].hw, gettid(), -1, -1, 0);
	if (fd == -1)
		err(1, "cannot attach event %s", fds[0].name);

	ov->fd = fd;
	ov->tid = gettid();
	ov->id = myid;
	ov->fds = fds;

	flags = fcntl(fd, F_GETFL, 0);
	if (fcntl(fd, F_SETFL, flags | O_ASYNC) < 0)
		err(1, "fcntl SETFL failed");

	fown_ex.type = F_OWNER_TID;
	fown_ex.pid  = gettid();
	ret = fcntl(fd,
		    (fown ? F_SETOWN_EX : F_SETOWN), 
		    (fown ? (unsigned long)&fown_ex: (unsigned long)gettid()));
	if (ret)
		err(1, "fcntl SETOWN failed");

	if (fcntl(fd, F_SETSIG, signum) < 0)
		err(1, "fcntl SETSIG failed");

	fds[0].buf = mmap(NULL, (buffer_pages + 1)* pgsz, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (fds[0].buf == MAP_FAILED)
		err(1, "cannot mmap buffer");
	
	fds[0].pgmsk = (buffer_pages * pgsz) - 1;

	printf("launch %s: fd: %d, tid: %d\n", name, fd, ov->tid);

	/*
 	 * activate event for wakeup_events (samples)
 	 */
	ret = ioctl(fd, PERF_EVENT_IOC_REFRESH , 1);
	if (ret == -1)
		err(1, "cannot refresh");

}

void
overflow_stop(void)
{
	int ret;
	ret = ioctl(fd2ov[myid].fd, PERF_EVENT_IOC_DISABLE, 0);
	if (ret)
		err(1, "cannot stop");
}

void *
my_thread(void *v)
{
	int retval = 0;
	
	myid = (unsigned long)v;

	pthread_barrier_wait(&barrier);

	overflow_start("side");
	do_cycles();
	overflow_stop();

	perf_free_fds(fds, num_fds);

	pthread_exit((void *)&retval);
}

static void
usage(void)
{
	printf("self_smpl_multi [-t secs] [-p period] [-s signal] [-f] [-n threads]\n"
		"-t secs: duration of the run in seconds\n"
		"-p period: sampling period in CPU cycles\n"
		"-s signal: signal to use (default: SIGIO)\n"
		"-n thread: number of threads to create (default: 1)\n"
		"-f : use F_SETOWN_EX for correct delivery of signal to thread (default: off)\n");
}

/*
 *  Program args: program_time, threshold, signum.
 */
int
main(int argc, char **argv)
{
	struct sigaction sa;
	pthread_t allthr[MAX_THR];
	sigset_t set, old, new;
	int i, ret, max_thr = 1;

	while ((i=getopt(argc, argv, "t:p:s:fhn:")) != EOF) {
		switch(i) {
		case 'h':
			usage();
			return 0;
		case 't':
			program_time = atoi(optarg);
			break;
		case 'p':
			threshold = atoi(optarg);
			break;
		case 's':
			signum = atoi(optarg);
			break;
		case 'f':
			fown = 1;
			break;
		case 'n':
			max_thr = atoi(optarg);
			if (max_thr >= MAX_THR)
				errx(1, "no more than %d threads", MAX_THR);
			break;
		default:
			errx(1, "invalid option");
		}
	}
	printf("program_time = %d, threshold = %d, signum = %d fcntl(%s), threads = %d\n",
		program_time, threshold, signum,
		fown ? "F_SETOWN_EX" : "F_SETOWN",
		max_thr);

	for (i = 0; i < MAX_THR; i++) {
		mismatch[i] = 0;
		bad_msg[i] = 0;
		bad_restart[i] = 0;
	}

	memset(&sa, 0, sizeof(sa));
	sigemptyset(&set);

	sa.sa_sigaction = sigusr1_handler;
	sa.sa_mask = set;
	sa.sa_flags = SA_SIGINFO;

	if (sigaction(SIGUSR1, &sa, NULL) != 0)
		errx(1, "sigaction failed");

	memset(&sa, 0, sizeof(sa));
	sigemptyset(&set);

	sa.sa_sigaction = sigio_handler;
	sa.sa_mask = set;
	sa.sa_flags = SA_SIGINFO;

	if (sigaction(signum, &sa, NULL) != 0)
		errx(1, "sigaction failed");

	if (pfm_initialize() != PFM_SUCCESS)
		errx(1, "pfm_initialize failed");

	/*
 	 * +1 because main thread is also using the barrier
 	 */
	pthread_barrier_init(&barrier, 0, max_thr+1);

	for(i=0; i < max_thr; i++) {
		ret = pthread_create(allthr+i, NULL, my_thread, (void *)(unsigned long)i);
		if (ret)
			err(1, "pthread_create failed");
	}
	myid = i;
	sigemptyset(&set);
	sigemptyset(&new);
	sigaddset(&set, SIGIO);
	sigaddset(&new, SIGIO);

	if (pthread_sigmask(SIG_BLOCK, &set, NULL))
		err(1, "cannot mask SIGIO in main thread");

	ret = sigprocmask(SIG_SETMASK, NULL, &old);
	if (ret)
		err(1, "sigprocmask failed");

	if (sigismember(&old, SIGIO)) {
		warnx("program started with SIGIO masked, unmasking it now\n");
		ret = sigprocmask(SIG_UNBLOCK, &new, NULL);
		if (ret)
			err(1, "sigprocmask failed");
	}

	pthread_barrier_wait(&barrier);
	printf("\n\n");

	for (i = 0; i < max_thr; i++) {
		pthread_join(allthr[i], NULL);
	}
	printf("\n\n");
	for (i = 0; i < max_thr; i++) {
		printf("myid = %3d, fd = %3d, total = %4ld, mismatch = %ld, "
			"bad_msg = %ld, bad_restart = %ld\n",
			fd2ov[i].id, fd2ov[i].fd, total[i], mismatch[i],
			bad_msg[i], bad_restart[i]);
	}
	/* free libpfm resources cleanly */
	pfm_terminate();

	return (0);
}
