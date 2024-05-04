#
# Copyright (c) 2010 Google, Inc
# Contributed by Stephane Eranian <eranian@gmail.com>
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

SRCS=validate.c

ifeq ($(CONFIG_PFMLIB_ARCH_X86),y)
SRCS += validate_x86.c
endif

ifeq ($(CONFIG_PFMLIB_ARCH_MIPS),y)
SRCS += validate_mips.c
endif

ifeq ($(CONFIG_PFMLIB_ARCH_ARM),y)
SRCS += validate_arm.c
endif

ifeq ($(CONFIG_PFMLIB_ARCH_ARM64),y)
SRCS += validate_arm64.c
endif

ifeq ($(CONFIG_PFMLIB_ARCH_POWERPC),y)
SRCS += validate_power.c
endif

ifeq ($(SYS),Linux)
SRCS += validate_perf.c
endif

CFLAGS+= -I. -D_GNU_SOURCE
LIBS += -lm

ifeq ($(SYS),Linux)
CFLAGS+= -pthread
endif

OBJS=$(SRCS:.c=.o)

TARGETS=validate

all: $(TARGETS)

validate: $(OBJS) $(PFMLIB)
	$(CC) $(CFLAGS) -o $@ $(LDFLAGS) $^ $(LIBS) 

clean:
	$(RM) -f *.o $(TARGETS) *~

distclean: clean

#
# examples are installed as part of the RPM install, typically in /usr/share/doc/libpfm-X.Y/
#
.PHONY: install depend install_examples
