#
# Copyright (c) 2002-2006 Hewlett-Packard Development Company, L.P.
# Contributed by Stephane Eranian <eranian@hpl.hp.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy 
# of this software and associated documentation files (the "Software"), to deal 
# in the Software without restriction, including without limitation the rights 
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies 
# of the Software, and to permit persons to whom the Software is furnished to do so, 
# subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all 
# copies or substantial portions of the Software.  
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF 
# CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE 
# OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

TOPDIR  := $(shell if [ "$$PWD" != "" ]; then echo $$PWD; else pwd; fi)/..

include $(TOPDIR)/config.mk
include $(TOPDIR)/rules.mk

DIRS=

ifeq ($(ARCH),ia64)
#DIRS +=ia64
endif

ifeq ($(ARCH),x86_64)
DIRS += x86
endif

ifeq ($(ARCH),i386)
DIRS += x86
endif

CFLAGS+= -I. -D_GNU_SOURCE -pthread

PERF_EVENT_HDR=$(TOPDIR)/include/perfmon/pfmlib_perf_event.h

LPC_UTILS=perf_util.o
LPC_UTILS_HDR=perf_util.h

TARGETS+=self self_basic self_count task task_attach_timeout syst \
	notify_self notify_group task_smpl self_smpl_multi \
	self_pipe syst_count task_cpu syst_smpl evt2raw \
	branch_smpl

# Make rtop conditional on ncurses development package installed
ifeq ($(shell /bin/echo -e '\#include <ncurses.h>\nint main(void) { return 0;}' | $(CC) -o /dev/null -xc - 2>/dev/null && echo -n yes), yes)
RTOP=rtop
endif

EXAMPLESDIR=$(DESTDIR)$(DOCDIR)/perf_examples

all: $(TARGETS) $(RTOP)
	@set -e ; for d in $(DIRS) ; do $(MAKE) -C $$d $@ ; done

rtop: rtop.o $(LPC_UTILS) $(PFMLIB) $(PERF_EVENT_HDR)
	$(CC) $(CFLAGS) -o $@ $(LDFLAGS) $< $(LPC_UTILS) $(PFMLIB) $(LIBS) -lpthread -lncurses -ltinfo -lm

$(TARGETS): %:%.o $(LPC_UTILS) $(PFMLIB)
	-$(CC) $(CFLAGS) -o $@ $(LDFLAGS) $< $(LPC_UTILS) $(PFMLIB) $(LIBS) 

$(LPC_UTILS): $(LPC_UTILS_HDR)

clean:
	@set -e ; for d in $(DIRS) ; do $(MAKE) -C $$d $@ ; done
	$(RM) -f *.o $(TARGETS) rtop *~

distclean: clean

install-examples install_examples: $(TARGETS)
	@echo installing: $(TARGETS)
	-mkdir -p $(EXAMPLESDIR)
	$(INSTALL) -m 755 $(TARGETS) $(EXAMPLESDIR)
	@set -e ; for d in $(DIRS) ; do $(MAKE) -C $$d $@ ; done
#
# examples are installed as part of the RPM install, typically in /usr/share/doc/libpfm-X.Y/
#
.PHONY: install depend install_examples install-examples
