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

#
# Look in config.mk for options
#
TOPDIR  := $(shell if [ "$$PWD" != "" ]; then echo $$PWD; else pwd; fi)

include config.mk

EXAMPLE_DIRS=examples
DIRS=lib tests $(EXAMPLE_DIRS) include docs

ifeq ($(SYS),Linux)
EXAMPLE_DIRS +=perf_examples
endif

ifneq ($(CONFIG_PFMLIB_NOPYTHON),y)
DIRS += python
endif

TAR=tar --exclude=.git --exclude=.gitignore
CURDIR=$(shell basename "$$PWD")
PKG=libpfm-4.$(REVISION).$(AGE)
TARBALL=$(PKG).tar.gz

all: 
	@echo Compiling for \'$(ARCH)\' target
	@echo Compiling for \'$(SYS)\' system
	@set -e ; for d in $(DIRS) ; do $(MAKE) -C $$d $@ ; done

lib:
	$(MAKE) -C lib

clean: 
	@set -e ; for d in $(DIRS) ; do $(MAKE) -C $$d $@ ; done

distclean:  clean
	@(cd debian; $(RM) -f *.log *.debhelper *.substvars; $(RM) -rf libpfm4-dev libpfm4 python-libpfm4 tmp files)
	$(RM) -f tags

depend: 
	@set -e ; for d in $(DIRS) ; do $(MAKE) -C $$d $@ ; done

tar: clean
	ln -s $$PWD ../$(PKG) && cd .. &&  $(TAR) -zcf $(TARBALL) $(PKG)/. && rm $(PKG)
	@echo generated ../$(TARBALL)

install-lib:
	@echo installing in $(DESTDIR)$(PREFIX)
	@$(MAKE) -C lib install
install install-all:
	@echo installing in $(DESTDIR)$(PREFIX)
	@set -e ; for d in $(DIRS) ; do $(MAKE) -C $$d install ; done
install-examples install_examples:
	@echo installing in $(DESTDIR)$(PREFIX)
	@set -e ; for d in $(EXAMPLE_DIRS) ; do $(MAKE) -C $$d $@ ; done

tags:
	@echo creating tags
	$(MAKE) -C lib $@

static:
	make all CONFIG_PFMLIB_SHARED=n

.PHONY: all clean distclean depend tar install install-all install-lib install-examples lib static install_examples

# DO NOT DELETE
