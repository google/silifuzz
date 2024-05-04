/*
 * pfmlib_sparc_ultra4.c : SPARC Ultra 4+
 *
 * Copyright (c) 2011 Google, Inc
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

/* private headers */
#include "pfmlib_priv.h"
#include "pfmlib_sparc_priv.h"
#include "events/sparc_ultra4plus_events.h"

pfmlib_pmu_t sparc_ultra4plus_support={
	.desc			= "Ultra Sparc 4+",
	.name			= "ultra4p",
	.pmu			= PFM_PMU_SPARC_ULTRA4PLUS, 
	.pme_count		= LIBPFM_ARRAY_SIZE(ultra4plus_pe),
	.type			= PFM_PMU_TYPE_CORE,
	.supported_plm		= SPARC_PLM,
	.max_encoding		= 2,
	.num_cntrs		= 2,
	.pe			= ultra4plus_pe,
	.atdesc			= NULL,
	.flags			= 0,

	.pmu_detect		= pfm_sparc_detect,
	.get_event_encoding[PFM_OS_NONE] = pfm_sparc_get_encoding,
	 PFMLIB_ENCODE_PERF(pfm_sparc_get_perf_encoding),
	.get_event_first	= pfm_sparc_get_event_first,
	.get_event_next		= pfm_sparc_get_event_next,
	.event_is_valid		= pfm_sparc_event_is_valid,
	.validate_table		= pfm_sparc_validate_table,
	.get_event_info		= pfm_sparc_get_event_info,
	.get_event_attr_info	= pfm_sparc_get_event_attr_info,
	 PFMLIB_VALID_PERF_PATTRS(pfm_sparc_perf_validate_pattrs),
	.get_event_nattrs	= pfm_sparc_get_event_nattrs,
};
