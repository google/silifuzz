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

from __future__ import print_function
import os
from perfmon import *

def public_members(self):
    s = "{ "
    for k, v in self.__dict__.items():
      if not k[0] == '_':
        s += "%s : %s, " % (k, v)
    s += " }"
    return s

class System:
  # Use the os that gives us everything
  os = PFM_OS_PERF_EVENT_EXT

  def __init__(self):
    self.ncpus = os.sysconf('SC_NPROCESSORS_ONLN')
    self.pmus = []
    for i in range(0, PFM_PMU_MAX):
      try:
        pmu = PMU(i)
      except:
        pass
      else:
        self.pmus.append(pmu)

  def __repr__(self):
    return public_members(self)

class Event:
  def __init__(self, info):
    self.info = info
    self.__attrs = []

  def __repr__(self):
    return '\n' + public_members(self)

  def __parse_attrs(self):
    info = self.info
    for index in range(0, info.nattrs):
      self.__attrs.append(pfm_get_event_attr_info(info.idx, index,
                                                  System.os)[1])

  def attrs(self):
    if not self.__attrs:
      self.__parse_attrs()
    return self.__attrs

class PMU:
  def __init__(self, i):
    self.info = pfm_get_pmu_info(i)[1]
    self.__events = []

  def __parse_events(self):
    index = self.info.first_event
    while index != -1:
      self.__events.append(Event(pfm_get_event_info(index, System.os)[1]))
      index = pfm_get_event_next(index)

  def events(self):
    if not self.__events:
      self.__parse_events()
    return self.__events

  def __repr__(self):
    return public_members(self)

if __name__ == '__main__':
  from perfmon import *
  s = System()
  for pmu in s.pmus:
    info = pmu.info
    if info.flags.is_present:
      print(info.name, info.size, info.nevents)
      for e in pmu.events():
        print(e.info.name, e.info.code)
        for a in e.attrs():
          print('\t\t', a.name, a.code)
