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

CFLAGS+= -I. -D_GNU_SOURCE
LIBS += -lm

ifeq ($(SYS),Linux)
CFLAGS+= -pthread
LIBS += -lrt
endif

ifeq ($(SYS),WINDOWS)
LIBS += -lgnurx
endif

TARGETS=showevtinfo check_events
EXAMPLESDIR=$(DESTDIR)$(DOCDIR)/examples

all: $(TARGETS)
	@set -e ; for d in $(DIRS) ; do $(MAKE) -C $$d $@ ; done

$(TARGETS):  %:%.o $(PFMLIB)
	$(CC) $(CFLAGS) -o $@ $(LDFLAGS) $^ $(LIBS) 
clean:
	@set -e ; for d in $(DIRS) ; do $(MAKE) -C $$d $@ ; done
	$(RM) -f *.o $(TARGETS) *~

distclean: clean

install-examples install_examples: $(TARGETS)
	@echo installing: $(TARGETS)
	-mkdir -p $(EXAMPLESDIR)
	$(INSTALL) -m 755 $(TARGETS) $(EXAMPLESDIR)
	@set -e ; for d in $(DIRS) ; do $(MAKE) -C $$d $@ ; done
#
# examples are installed as part of the RPM install, typically in /usr/share/doc/libpfm-X.Y/
#
.PHONY: install depend install-example install_examples
