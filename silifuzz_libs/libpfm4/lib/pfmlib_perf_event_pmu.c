/*
 * pfmlib_perf_pmu.c: support for perf_events event table
 *
 * Copyright (c) 2009 Google, Inc
 * Contributed by Stephane Eranian <eranian@google.com>
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
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#ifdef __linux__
#include <sys/syscall.h> /* for openat() */
#include <sys/param.h>
#endif

#include "pfmlib_priv.h"
#include "pfmlib_perf_event_priv.h"

#define PERF_MAX_UMASKS	8

typedef struct {
	const char	*uname;	/* unit mask name */
	const char	*udesc;	/* unit mask desc */
	uint64_t	uid;	/* unit mask id */
	int		uflags;	/* umask options */
	int		grpid;	/* group identifier */
} perf_umask_t;
	
typedef struct {
	const char	*name;			/* name */
	const char	*desc;			/* description */
	const char	*equiv;			/* event is aliased to */
	const char	*pmu;			/* PMU instance (sysfs) */
	uint64_t	id;			/* perf_hw_id or equivalent */
	int		modmsk;			/* modifiers bitmask */
	int		type;			/* perf_type_id */
	int		numasks;		/* number of unit masls */
	int		ngrp;			/* number of umasks groups */
	unsigned long	umask_ovfl_idx;		/* base index of overflow unit masks */
	int		flags;			/* evnet flags */
	perf_umask_t	umasks[PERF_MAX_UMASKS];/* first unit masks */
} perf_event_t;

/*
 * event/umask flags
 */
#define PERF_FL_DEFAULT	0x1	/* umask is default for group */
#define PERF_FL_PRECISE	0x2	/* support precise sampling */

#define PERF_INVAL_OVFL_IDX (~0UL)

#define PCL_EVT(f, t, m, fl)	\
	{ .name = #f,		\
	  .id = (f),		\
	  .type = (t),		\
	  .desc = #f,		\
	  .equiv = NULL,	\
	  .numasks = 0,		\
	  .modmsk = (m),	\
	  .ngrp = 0,		\
	  .flags = fl,		\
	  .umask_ovfl_idx = PERF_INVAL_OVFL_IDX,\
	}

#define PCL_EVTA(f, t, m, a, fl)\
	{ .name = #f,		\
	  .id = a,		\
	  .type = t,		\
	  .desc = #a,		\
	  .equiv = #a,		\
	  .numasks = 0,		\
	  .modmsk = m,		\
	  .ngrp = 0,		\
	  .flags = fl,		\
	  .umask_ovfl_idx = PERF_INVAL_OVFL_IDX,\
	}

#define PCL_EVTR(f, t, a, d)\
	{ .name = #f,		\
	  .id = a,		\
	  .type = t,		\
	  .desc = d,		\
	  .umask_ovfl_idx = PERF_INVAL_OVFL_IDX,\
	}


#define PCL_EVT_HW(n) PCL_EVT(PERF_COUNT_HW_##n, PERF_TYPE_HARDWARE, PERF_ATTR_HW, 0)
#define PCL_EVT_SW(n) PCL_EVT(PERF_COUNT_SW_##n, PERF_TYPE_SOFTWARE, PERF_ATTR_SW, 0)
#define PCL_EVT_AHW(n, a) PCL_EVTA(n, PERF_TYPE_HARDWARE, PERF_ATTR_HW, PERF_COUNT_HW_##a, 0)
#define PCL_EVT_ASW(n, a) PCL_EVTA(n, PERF_TYPE_SOFTWARE, PERF_ATTR_SW, PERF_COUNT_SW_##a, 0)
#define PCL_EVT_HW_FL(n, fl) PCL_EVT(PERF_COUNT_HW_##n, PERF_TYPE_HARDWARE, PERF_ATTR_HW, fl)
#define PCL_EVT_RAW(n, e, u, d) PCL_EVTR(n, PERF_TYPE_RAW, (u) << 8 | (e), d)

#ifndef MAXPATHLEN
#define MAXPATHLEN	1024
#endif

#define PERF_ATTR_HW 0
#define PERF_ATTR_SW 0

#include "events/perf_events.h"

#define perf_nevents (perf_event_support.pme_count)

static perf_event_t *perf_pe = perf_static_events;
static perf_event_t  *perf_pe_free, *perf_pe_end;
static perf_umask_t *perf_um, *perf_um_free, *perf_um_end;
static int perf_pe_count;

static inline int
pfm_perf_pmu_supported_plm(void *this)
{
	pfmlib_pmu_t *pmu;

	pmu = pfmlib_get_pmu_by_type(PFM_PMU_TYPE_CORE);
	if (!pmu) {
		DPRINT("no core CPU PMU, going with default\n");
		pmu = this;
	} else {
		DPRINT("guessing plm from %s PMU plm=0x%x\n", pmu->name, pmu->supported_plm);
	}
	return pmu->supported_plm;
}

static inline unsigned long
perf_get_ovfl_umask_idx(perf_umask_t *um)
{
	return um - perf_um;
}

static inline perf_umask_t *
perf_get_ovfl_umask(int pidx)
{
	return perf_um+perf_pe[pidx].umask_ovfl_idx;
}

static inline perf_umask_t *
perf_attridx2um(int idx, int attr_idx)
{
	perf_umask_t *um;

	if (attr_idx < PERF_MAX_UMASKS) {
		um = &perf_pe[idx].umasks[attr_idx];
	} else {
		um  = perf_get_ovfl_umask(idx);
		um += attr_idx - PERF_MAX_UMASKS;
	}

	return um;
}



#define PERF_ALLOC_EVENT_COUNT	(512)
#define PERF_ALLOC_UMASK_COUNT	(1024)

/*
 * clone static event table into a  dynamic
 * event table
 *
 * Used for tracepoints
 */
static perf_event_t *
perf_table_clone(void)
{
	perf_event_t *addr;

	perf_pe_count = perf_nevents + PERF_ALLOC_EVENT_COUNT;

	addr = calloc(perf_pe_count, sizeof(perf_event_t));
	if (addr) {
		memcpy(addr, perf_static_events, perf_nevents * sizeof(perf_event_t));
		perf_pe_free = addr + perf_nevents;
		perf_pe_end = perf_pe_free + PERF_ALLOC_EVENT_COUNT;
		perf_pe = addr;
	}
	return addr;
}
static inline int perf_pe_allocated(void)
{
	return perf_pe != perf_static_events;
}
/*
 * allocate space for one new event in event table
 *
 * returns NULL if out-of-memory
 *
 * may realloc existing table if necessary for growth
 */
static perf_event_t *
perf_table_alloc_event(void)
{
	perf_event_t *new_pe;
	perf_event_t *p;
	size_t num_free;

	/*
	 * if we need to allocate an event and we have not yet
	 * cloned the static events, then clone them
	 */
	if (!perf_pe_allocated()) {
		DPRINT("cloning static event table\n");
		p = perf_table_clone();
		if (!p)
			return NULL;
		perf_pe = p;
	}
retry:
	if (perf_pe_free < perf_pe_end)
		return perf_pe_free++;

	perf_pe_count += PERF_ALLOC_EVENT_COUNT;
	
	/*
	 * compute number of free events left
	 * before realloc() to avoid compiler warning (use-after-free)
	 * even though we are simply doing pointer arithmetic and not
	 * dereferencing the perf_pe after realloc when it may be stale
	 * in case the memory was moved.
	 */
	num_free = perf_pe_free - perf_pe;

	new_pe = realloc(perf_pe, perf_pe_count * sizeof(perf_event_t));
	if (!new_pe) 
		return NULL;
	
	perf_pe_free = new_pe + num_free;
	perf_pe_end = perf_pe_free + PERF_ALLOC_EVENT_COUNT;
	perf_pe = new_pe;

	goto retry;
}

#ifndef CONFIG_PFMLIB_NOTRACEPOINT
static int perf_um_count;
static char debugfs_mnt[MAXPATHLEN];
/*
 * figure out the mount point of the debugfs filesystem
 *
 * returns -1 if none is found
 */
static int
get_debugfs_mnt(void)
{
	FILE *fp;
	char *buffer = NULL;
	size_t len = 0;
	char *q, *mnt, *fs;
	int res = -1;

	fp = fopen("/proc/mounts", "r");
	if (!fp)
		return -1;

	while(pfmlib_getl(&buffer, &len, fp) != -1) {

		q = strchr(buffer, ' ');
		if (!q)
			continue;
		mnt = ++q;
		q = strchr(q, ' ');
		if (!q)
			continue;
		*q = '\0';

		fs = ++q;
		q = strchr(q, ' ');
		if (!q)
			continue;
		*q = '\0';

		if (!strcmp(fs, "debugfs")) {
			strncpy(debugfs_mnt, mnt, MAXPATHLEN);
			debugfs_mnt[MAXPATHLEN-1]= '\0';
			res = 0;
			break;
		}
	}
	free(buffer);

	fclose(fp);

	return res;
}

/*
 * allocate space for overflow new unit masks
 *
 * Each event can hold up to PERF_MAX_UMASKS.
 * But gievn we can dynamically add events
 * which may have more unit masks, then we
 * put them into a separate overflow unit
 * masks,  table which can grow on demand.
 * In that case the first PERF_MAX_UMASKS
 * are in the event, the rest in the overflow
 * table at index pointed to by event->umask_ovfl_idx
 * All unit masks for an event are contiguous in the
 * overflow table.
 */
static perf_umask_t *
perf_table_alloc_umask(void)
{
	perf_umask_t *new_um;
	size_t num_free;

retry:
	if (perf_um_free < perf_um_end)
		return perf_um_free++;

	perf_um_count += PERF_ALLOC_UMASK_COUNT;

	/*
	 * compute number of free unmasks left
	 * before realloc() to avoid compiler warning (use-after-free)
	 * even though we are simply doing pointer arithmetic and not
	 * dereferencing the perf_um after realloc when it may be stale
	 * in case the memory was moved.
	 */
	num_free = perf_um_free - perf_um;
	new_um = realloc(perf_um, perf_um_count * sizeof(*new_um));
	if (!new_um) 
		return NULL;
	
	perf_um_free = new_um + num_free;
	perf_um_end = perf_um_free + PERF_ALLOC_UMASK_COUNT;
	perf_um = new_um;

	goto retry;
}

#ifdef __GNUC__
#define POTENTIALLY_UNUSED __attribute__((unused))
#endif

static void
gen_tracepoint_table(void)
{
	DIR *dir1, *dir2;
	struct dirent *d1, *d2;
	perf_event_t *p = NULL;
	perf_umask_t *um;
	char POTENTIALLY_UNUSED d2path[MAXPATHLEN];
	char idpath[MAXPATHLEN];
	char id_str[32];
	uint64_t id;
	int fd, err;
	int POTENTIALLY_UNUSED dir1_fd;
	int POTENTIALLY_UNUSED dir2_fd;
	int reuse_event = 0;
	int numasks;
	char *tracepoint_name;
	int retlen;

	err = get_debugfs_mnt();
	if (err == -1)
		return;

	strncat(debugfs_mnt, "/tracing/events", MAXPATHLEN-1);
	debugfs_mnt[MAXPATHLEN-1]= '\0';

#ifdef HAS_OPENAT
	dir1_fd = open(debugfs_mnt, O_DIRECTORY);
	if (dir1_fd < 0)
		return;

	dir1 = fdopendir(dir1_fd);
#else
	dir1 = opendir(debugfs_mnt);
	if (!dir1)
		return;
#endif

	err = 0;
	while((d1 = readdir(dir1)) && err >= 0) {

		if (!strcmp(d1->d_name, "."))
			continue;

		if (!strcmp(d1->d_name, ".."))
			continue;

#ifdef HAS_OPENAT
		/* fails if it cannot open */
		dir2_fd = openat(dir1_fd, d1->d_name, O_DIRECTORY);
		if (dir2_fd < 0)
			continue;

		dir2 = fdopendir(dir2_fd);
		if (!dir2)
			continue;
#else
		retlen = snprintf(d2path, MAXPATHLEN, "%s/%s", debugfs_mnt, d1->d_name);
		/* ensure generated d2path string is valid */
		if (retlen <= 0 || MAXPATHLEN <= retlen)
			continue;

		/* fails if d2path is not a directory */
		dir2 = opendir(d2path);
		if (!dir2)
			continue;
#endif
		dir2_fd = dirfd(dir2);

		/*
 		 * if a subdir did not fit our expected
 		 * tracepoint format, then we reuse the
		 * allocated space (with have no free)
 		 */
		if (!reuse_event)
			p = perf_table_alloc_event();

		if (!p)
			break;

		if (p)
			p->name = tracepoint_name = strdup(d1->d_name);

		if (!(p && p->name)) {
			closedir(dir2);
			err = -1;
			continue;
		}

		p->desc = "tracepoint";
		p->id = ~0ULL;
		p->type = PERF_TYPE_TRACEPOINT;
		p->umask_ovfl_idx = PERF_INVAL_OVFL_IDX;
		p->modmsk = 0,
		p->ngrp = 1;

		numasks = 0;
		reuse_event = 0;

		while((d2 = readdir(dir2))) {
			if (!strcmp(d2->d_name, "."))
				continue;

			if (!strcmp(d2->d_name, ".."))
				continue;

#ifdef HAS_OPENAT
			retlen = snprintf(idpath, MAXPATHLEN, "%s/id", d2->d_name);
			/* ensure generated d2path string is valid */
			if (retlen <= 0 || MAXPATHLEN <= retlen)
				continue;

                        fd = openat(dir2_fd, idpath, O_RDONLY);
#else
                        retlen = snprintf(idpath, MAXPATHLEN, "%s/%s/id", d2path, d2->d_name);
			/* ensure generated d2path string is valid */
			if (retlen <= 0 || MAXPATHLEN <= retlen)
				continue;

                        fd = open(idpath, O_RDONLY);
#endif
			if (fd == -1)
				continue;

			err = read(fd, id_str, sizeof(id_str));

			close(fd);

			if (err < 0)
				continue;

			id = strtoull(id_str, NULL, 0);

			if (numasks < PERF_MAX_UMASKS)
				um = p->umasks+numasks;
			else {
				um = perf_table_alloc_umask();
				if (numasks == PERF_MAX_UMASKS)
					p->umask_ovfl_idx = perf_get_ovfl_umask_idx(um);
			}

			if (!um) {
				err = -1;
				break;
			}

			/*
			 * tracepoint have no event codes
			 * the code is in the unit masks
			 */
			p->id = 0;

			um->uname = strdup(d2->d_name);
			if (!um->uname) {
				err = -1;
				break;
			}
			um->udesc = um->uname;
			um->uid   = id;
			um->grpid = 0;
			DPRINT("idpath=%s:%s id=%"PRIu64"\n", p->name, um->uname, id);
			numasks++;
		}
		p->numasks = numasks;

		closedir(dir2);

		/*
		 * directory was not pointing
		 * to a tree structure we know about
		 */
		if (!numasks) {
			free(tracepoint_name);
			reuse_event = 1;
			continue;
		}

		/*
 		 * update total number of events
 		 * only when no error is reported
 		 */
		if (err >= 0)
			perf_nevents++;
		reuse_event = 0;
	}
	closedir(dir1);
}
#endif /* CONFIG_PFMLIB_NOTRACEPOINT */

static int
pfm_perf_detect(void *this)
{
#ifdef __linux__
	/* ought to find a better way of detecting PERF */
#define PERF_OLD_PROC_FILE "/proc/sys/kernel/perf_counter_paranoid"
#define PERF_PROC_FILE "/proc/sys/kernel/perf_event_paranoid"
	return !(access(PERF_PROC_FILE, F_OK)
		  && access(PERF_OLD_PROC_FILE, F_OK)) ? PFM_SUCCESS: PFM_ERR_NOTSUPP;
#else
	return PFM_SUCCESS;
#endif
}

/*
 * checks that the event is exported by the PMU specified by the event entry
 * This code assumes the PMU type is RAW, which requires an encoding exported
 * via sysfs.
 */
static int
event_exist(perf_event_t *e)
{
	char buf[PATH_MAX];

	snprintf(buf, PATH_MAX, "/sys/devices/%s/events/%s", e->pmu ? e->pmu : "cpu", e->name);

	return access(buf, F_OK) == 0;
}

static void
add_optional_events(void)
{
	perf_event_t *ent, *e;
	size_t i;

	for (i = 0; i < PME_PERF_EVENT_OPT_COUNT; i++) {

		e = perf_optional_events + i;

		if (!event_exist(e)) {
			DPRINT("perf::%s not available\n", e->name);
			continue;
		}

		ent = perf_table_alloc_event();
		if (!ent)
			break;
		memcpy(ent, e, sizeof(*e));

		perf_nevents++;
	}
}

static int
pfm_perf_init(void *this)
{
	pfmlib_pmu_t *pmu = this;

	perf_pe = perf_static_events;

	/*
	 * we force the value of pme_count by hand because
	 * the library could be initialized mutltiple times
	 * due to pfm_terminate() and thus we need to start
	 * from the default count
	 */
	perf_event_support.pme_count = PME_PERF_EVENT_COUNT;

#ifndef CONFIG_PFMLIB_NOTRACEPOINT
	/* must dynamically add tracepoints */
	gen_tracepoint_table();
#endif

	/* must dynamically add optional hw events */
	add_optional_events();

	/* dynamically patch supported plm based on CORE PMU plm */
	pmu->supported_plm = pfm_perf_pmu_supported_plm(pmu);

	return PFM_SUCCESS;
}

static int
pfm_perf_get_event_first(void *this)
{
	return 0;
}

static int
pfm_perf_get_event_next(void *this, int idx)
{
	if (idx < 0 || idx >= (perf_nevents-1))
		return -1;

	return idx+1;
}

static int
pfm_perf_add_defaults(pfmlib_event_desc_t *e, unsigned int msk, uint64_t *umask)
{
	perf_event_t *ent;
	perf_umask_t *um;
	int i, j, k, added;

	k = e->nattrs;
	ent = perf_pe+e->event;

	for(i=0; msk; msk >>=1, i++) {

		if (!(msk & 0x1))
			continue;

		added = 0;

		for(j=0; j < ent->numasks; j++) {

			if (j < PERF_MAX_UMASKS) {
				um = &perf_pe[e->event].umasks[j];
			} else {
				um = perf_get_ovfl_umask(e->event);
				um += j - PERF_MAX_UMASKS;
			}
			if (um->grpid != i)
				continue;

			if (um->uflags & PERF_FL_DEFAULT) {
				DPRINT("added default %s for group %d\n", um->uname, i);

				*umask |= um->uid;

				e->attrs[k].id = j;
				e->attrs[k].ival = 0;
				k++;

				added++;
			}
		}
		if (!added) {
			DPRINT("no default found for event %s unit mask group %d\n", ent->name, i);
			return PFM_ERR_UMASK;
		}
	}
	e->nattrs = k;
	return PFM_SUCCESS;
}

static int
pfmlib_perf_encode_tp(pfmlib_event_desc_t *e)
{
	perf_umask_t *um;
	pfmlib_event_attr_info_t *a;
	int i, nu = 0;

	e->fstr[0] = '\0';
	e->count = 1;
	evt_strcat(e->fstr, "%s", perf_pe[e->event].name);
	/*
	 * look for tracepoints
	 */
	for(i=0; i < e->nattrs; i++) {
		a = attr(e, i);
		if (a->ctrl != PFM_ATTR_CTRL_PMU)
			continue;

		if (a->type == PFM_ATTR_UMASK) {
			/*
			 * tracepoint unit masks cannot be combined
			 */
			if (++nu > 1)
				return PFM_ERR_FEATCOMB;

			if (a->idx < PERF_MAX_UMASKS) {
				e->codes[0] = perf_pe[e->event].umasks[a->idx].uid;
				evt_strcat(e->fstr, ":%s", perf_pe[e->event].umasks[a->idx].uname);
			} else {
				um = perf_get_ovfl_umask(e->event);
				e->codes[0] = um[a->idx - PERF_MAX_UMASKS].uid;
				evt_strcat(e->fstr, ":%s", um[a->idx - PERF_MAX_UMASKS].uname);
			}
		} else
			return PFM_ERR_ATTR;
	}
	return PFM_SUCCESS;
}

static int
pfmlib_perf_encode_hw_cache(pfmlib_event_desc_t *e)
{
	pfmlib_event_attr_info_t *a;
	perf_event_t *ent;
	unsigned int msk, grpmsk;
	uint64_t umask = 0;
	int i, ret;

	grpmsk = (1 << perf_pe[e->event].ngrp)-1;

	ent = perf_pe + e->event;

	e->codes[0] = ent->id;
	e->count = 1;

	e->fstr[0] = '\0';

	for(i=0; i < e->nattrs; i++) {
		a = attr(e, i);
		if (a->ctrl != PFM_ATTR_CTRL_PMU)
			continue;
		if (a->type == PFM_ATTR_UMASK) {
			e->codes[0] |= ent->umasks[a->idx].uid;

			msk = 1 << ent->umasks[a->idx].grpid;
			/* umask cannot be combined in each group */
			if ((grpmsk & msk) == 0)
				return PFM_ERR_UMASK;
			grpmsk &= ~msk;
		} else
			return PFM_ERR_ATTR; /* no mod, no raw umask */
	}

	/* check for missing default umasks */
	if (grpmsk) {
		ret = pfm_perf_add_defaults(e, grpmsk, &umask);
		if (ret != PFM_SUCCESS)
			return ret;
		e->codes[0] |= umask;
	}

	/*
	 * reorder all the attributes such that the fstr appears always
	 * the same regardless of how the attributes were submitted.
	 *
	 * cannot sort attr until after we have added the default umasks
	 */
	evt_strcat(e->fstr, "%s", ent->name);
	pfmlib_sort_attr(e);
	for(i=0; i < e->nattrs; i++) {
		a = attr(e, i);
		if (a->ctrl != PFM_ATTR_CTRL_PMU)
			continue;
		if (a->type == PFM_ATTR_UMASK)
			evt_strcat(e->fstr, ":%s", ent->umasks[a->idx].uname);
	}
	return PFM_SUCCESS;
}

static int
pfm_perf_get_encoding(void *this, pfmlib_event_desc_t *e)
{
	int ret;

	switch(perf_pe[e->event].type) {
	case PERF_TYPE_TRACEPOINT:
		ret = pfmlib_perf_encode_tp(e);
		break;
	case PERF_TYPE_HW_CACHE:
		ret = pfmlib_perf_encode_hw_cache(e);
		break;
	case PERF_TYPE_HARDWARE:
	case PERF_TYPE_SOFTWARE:
	case PERF_TYPE_RAW:
		ret = PFM_SUCCESS;
		e->codes[0] = perf_pe[e->event].id;
		e->count = 1;
		e->fstr[0] = '\0';
		evt_strcat(e->fstr, "%s", perf_pe[e->event].name);
		break;
	default:
		DPRINT("unsupported event type=%d\n", perf_pe[e->event].type);
		return PFM_ERR_NOTSUPP;
	}

	return ret;
}

static int
pfm_perf_get_perf_encoding(void *this, pfmlib_event_desc_t *e)
{
	struct perf_event_attr *attr;
	int ret;

	switch(perf_pe[e->event].type) {
	case PERF_TYPE_TRACEPOINT:
		ret = pfmlib_perf_encode_tp(e);
		break;
	case PERF_TYPE_HW_CACHE:
		ret = pfmlib_perf_encode_hw_cache(e);
		break;
	case PERF_TYPE_HARDWARE:
	case PERF_TYPE_SOFTWARE:
	case PERF_TYPE_RAW:
		ret = PFM_SUCCESS;
		e->codes[0] = perf_pe[e->event].id;
		e->count = 1;
		e->fstr[0] = '\0';
		evt_strcat(e->fstr, "%s", perf_pe[e->event].name);
		break;
	default:
		DPRINT("unsupported event type=%d\n", perf_pe[e->event].type);
		return PFM_ERR_NOTSUPP;
	}

	attr = e->os_data;
	attr->type = perf_pe[e->event].type;
	attr->config = e->codes[0];

	return ret;
}


static int
pfm_perf_event_is_valid(void *this, int idx)
{
	return idx >= 0 && idx < perf_nevents;
}

static int
pfm_perf_get_event_attr_info(void *this, int idx, int attr_idx, pfmlib_event_attr_info_t *info)
{
	perf_umask_t *um;

	/* only supports umasks, modifiers handled at OS layer */
	um = perf_attridx2um(idx, attr_idx);

	info->name = um->uname;
	info->desc = um->udesc;
	info->equiv= NULL;
	info->code = um->uid;
	info->type = PFM_ATTR_UMASK;
	info->ctrl = PFM_ATTR_CTRL_PMU;

	info->is_precise =  !!(um->uflags & PERF_FL_PRECISE);
	info->support_hw_smpl = info->is_precise;
	info->is_dfl = 0;
	info->idx = attr_idx;
	info->dfl_val64 = 0;

	return PFM_SUCCESS;
}

static int
pfm_perf_get_event_info(void *this, int idx, pfm_event_info_t *info)
{
	pfmlib_pmu_t *pmu = this;
	info->name  = perf_pe[idx].name;
	info->desc  = perf_pe[idx].desc;
	info->code  = perf_pe[idx].id;
	info->equiv = perf_pe[idx].equiv;
	info->idx   = idx;
	info->pmu   = pmu->pmu;
	info->is_precise =  !!(perf_pe[idx].flags & PERF_FL_PRECISE);
	info->support_hw_smpl = info->is_precise;

	/* unit masks + modifiers */
	info->nattrs  = perf_pe[idx].numasks;

	return PFM_SUCCESS;
}

static void
pfm_perf_terminate(void *this)
{
	perf_event_t *p;
	int i, j;

	/* if perf_pe not allocated then perf_um not allocated */
	if (!perf_pe_allocated())
		return;

	/*
	 * free tracepoints name + unit mask names
	 * which are dynamically allocated
	 */
	for (i = 0; i < perf_nevents; i++) {
		p = &perf_pe[i];

		if (p->type != PERF_TYPE_TRACEPOINT)
			continue;

		/* cast to keep compiler happy, we are
		 * freeing the dynamically allocated clone
		 * table, not the static one. We do not want
		 * to create a specific data type
		 */
		free((void *)p->name);

		/*
		 * first PERF_MAX_UMASKS are pre-allocated
		 * the rest is in a separate dynamic table
		 */
		for (j = 0; j < p->numasks; j++) {
			if (j == PERF_MAX_UMASKS)
				break;
			free((void *)p->umasks[j].uname);
		}
	}
	/*
	 * perf_pe is systematically allocated
	 */
	if (perf_pe_allocated()) {
		free(perf_pe);
		perf_pe = perf_pe_free = perf_pe_end = NULL;
	}

	if (perf_um) {
		int n;
		/*
		 * free the dynamic umasks' uname
		 */
		n = perf_um_free - perf_um;
		for(i=0; i < n; i++)
			free((void *)(perf_um[i].uname));
		free(perf_um);
		perf_um = NULL;
		perf_um_free = perf_um_end = NULL;
	}
}

static int
pfm_perf_validate_table(void *this, FILE *fp)
{
	const char *name = perf_event_support.name;
	perf_umask_t *um;
	int i, j;
	int error = 0;

	for(i=0; i < perf_event_support.pme_count; i++) {

		if (!perf_pe[i].name) {
			fprintf(fp, "pmu: %s event%d: :: no name (prev event was %s)\n", name, i,
			i > 1 ? perf_pe[i-1].name : "??");
			error++;
		}

		if (!perf_pe[i].desc) {
			fprintf(fp, "pmu: %s event%d: %s :: no description\n", name, i, perf_pe[i].name);
			error++;
		}

		if (perf_pe[i].type < PERF_TYPE_HARDWARE || perf_pe[i].type >= PERF_TYPE_MAX) {
			fprintf(fp, "pmu: %s event%d: %s :: invalid type\n", name, i, perf_pe[i].name);
			error++;
		}

		if (perf_pe[i].numasks > PERF_MAX_UMASKS && perf_pe[i].umask_ovfl_idx == PERF_INVAL_OVFL_IDX) {
			fprintf(fp, "pmu: %s event%d: %s :: numasks too big (<%d)\n", name, i, perf_pe[i].name, PERF_MAX_UMASKS);
			error++;
		}

		if (perf_pe[i].numasks < PERF_MAX_UMASKS && perf_pe[i].umask_ovfl_idx != PERF_INVAL_OVFL_IDX) {
			fprintf(fp, "pmu: %s event%d: %s :: overflow umask idx defined but not needed (<%d)\n", name, i, perf_pe[i].name, PERF_MAX_UMASKS);
			error++;
		}

		if (perf_pe[i].numasks && perf_pe[i].ngrp == 0) {
			fprintf(fp, "pmu: %s event%d: %s :: ngrp cannot be zero\n", name, i, perf_pe[i].name);
			error++;
		}

		if (perf_pe[i].numasks == 0 && perf_pe[i].ngrp) {
			fprintf(fp, "pmu: %s event%d: %s :: ngrp must be zero\n", name, i, perf_pe[i].name);
			error++;
		}

		for(j = 0; j < perf_pe[i].numasks; j++) {

			if (j < PERF_MAX_UMASKS){
				um = perf_pe[i].umasks+j;
			} else {
				um = perf_get_ovfl_umask(i);
				um += j - PERF_MAX_UMASKS;
			}
			if (!um->uname) {
				fprintf(fp, "pmu: %s event%d: %s umask%d :: no name\n", name, i, perf_pe[i].name, j);
				error++;
			}

			if (!um->udesc) {
				fprintf(fp, "pmu: %s event%d:%s umask%d: %s :: no description\n", name, i, perf_pe[i].name, j, um->uname);
				error++;
			}

			if (perf_pe[i].ngrp && um->grpid >= perf_pe[i].ngrp) {
				fprintf(fp, "pmu: %s event%d: %s umask%d: %s :: invalid grpid %d (must be < %d)\n", name, i, perf_pe[i].name, j, um->uname, um->grpid, perf_pe[i].ngrp);
				error++;
			}
		}

		/* check for excess unit masks */
		for(; j < PERF_MAX_UMASKS; j++) {
			if (perf_pe[i].umasks[j].uname || perf_pe[i].umasks[j].udesc) {
				fprintf(fp, "pmu: %s event%d: %s :: numasks (%d) invalid more events exists\n", name, i, perf_pe[i].name, perf_pe[i].numasks);
				error++;
			}
		}
	}
	return error ? PFM_ERR_INVAL : PFM_SUCCESS;
}

static unsigned int
pfm_perf_get_event_nattrs(void *this, int idx)
{
	return perf_pe[idx].numasks;
}

/*
 * this function tries to figure out what the underlying core PMU
 * priv level masks are. It looks for a TYPE_CORE PMU and uses the
 * first event to determine supported priv level masks.
 */
/*
 * remove attrs which are in conflicts (or duplicated) with os layer
 */
static void
pfm_perf_perf_validate_pattrs(void *this, pfmlib_event_desc_t *e)
{
	pfmlib_pmu_t *pmu = this;
	int i, compact, type;
	int plm = pmu->supported_plm;

	for (i = 0; i < e->npattrs; i++) {
		compact = 0;

		/* umasks never conflict */
		if (e->pattrs[i].type == PFM_ATTR_UMASK)
			continue;

		if (e->pattrs[i].ctrl != PFM_ATTR_CTRL_PERF_EVENT)
			continue;

		/*
		 * only PERF_TYPE_HARDWARE/HW_CACHE may have
		 * precise mode or hypervisor mode
		 *
		 * there is no way to know for sure for those events
		 * so we allow the modifiers and leave it to the kernel
		 * to decide
		 */
		type = perf_pe[e->event].type;
		if (type == PERF_TYPE_HARDWARE || type == PERF_TYPE_HW_CACHE) {
			/* no hypervisor mode */
			if (e->pattrs[i].idx == PERF_ATTR_H && !(plm & PFM_PLMH))
				compact = 1;

			/* no user mode */
			if (e->pattrs[i].idx == PERF_ATTR_U && !(plm & PFM_PLM3))
				compact = 1;

			/* no kernel mode */
			if (e->pattrs[i].idx == PERF_ATTR_K && !(plm & PFM_PLM0))
				compact = 1;
		} else {
			if (e->pattrs[i].idx == PERF_ATTR_PR)
				compact = 1;

			/* no hypervisor mode */
			if (e->pattrs[i].idx == PERF_ATTR_H)
				compact = 1;
		}

		/* hardware sampling not supported */
		if (e->pattrs[i].idx == PERF_ATTR_HWS)
			compact = 1;

		if (compact) {
			pfmlib_compact_pattrs(e, i);
			i--;
		}
	}
}

pfmlib_pmu_t perf_event_support={
	.desc			= "perf_events generic PMU",
	.name			= "perf",
	.pmu			= PFM_PMU_PERF_EVENT,
	.pme_count		= PME_PERF_EVENT_COUNT,
	.type			= PFM_PMU_TYPE_OS_GENERIC,
	.max_encoding		= 1,
	.supported_plm		= PERF_PLM_ALL,
	.pmu_detect		= pfm_perf_detect,
	.pmu_init		= pfm_perf_init,
	.pmu_terminate		= pfm_perf_terminate,
	.get_event_encoding[PFM_OS_NONE] = pfm_perf_get_encoding,
	 PFMLIB_ENCODE_PERF(pfm_perf_get_perf_encoding),
	.get_event_first	= pfm_perf_get_event_first,
	.get_event_next		= pfm_perf_get_event_next,
	.event_is_valid		= pfm_perf_event_is_valid,
	.get_event_info		= pfm_perf_get_event_info,
	.get_event_attr_info	= pfm_perf_get_event_attr_info,
	.validate_table		= pfm_perf_validate_table,
	.get_event_nattrs	= pfm_perf_get_event_nattrs,
	 PFMLIB_VALID_PERF_PATTRS(pfm_perf_perf_validate_pattrs),
};
