#!/usr/bin/env python
#
# Copyright (c) 2008 Google, Inc.
# Contributed by Arun Sharma <arun.sharma@google.com>
# 
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
# 
# System wide monitoring example. Copied from syst.c
#
# Run as: ./sys.py -c cpulist -e eventlist

from __future__ import print_function
import sys
import os
import optparse
import time 
import struct
import perfmon

if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("-e", "--events", help="Events to use",
		       action="store", dest="events")
    parser.add_option("-c", "--cpulist", help="CPUs to monitor",
		       action="store", dest="cpulist")
    parser.set_defaults(cpulist="0")
    parser.set_defaults(events="PERF_COUNT_HW_CPU_CYCLES")
    (options, args) = parser.parse_args()

    cpus = options.cpulist.split(',')
    cpus = [ int(c) for c in cpus ] 

    if options.events:
      events = options.events.split(",")
    else:
      raise Exception("You need to specify events to monitor")

    s = perfmon.SystemWideSession(cpus, events)

    s.start()
    # Measuring loop
    while 1:
      time.sleep(1)
      # read the counts
      for c in cpus:
        for i in range(0, len(events)):
          count = struct.unpack("L", s.read(c, i))[0]
          print("""CPU%d: %s\t%lu""" % (c, events[i], count))
