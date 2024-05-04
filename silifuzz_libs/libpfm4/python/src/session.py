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

from perfmon import *
import os
import sys

# Common base class
class Session:
  def __init__(self, events):
    self.system = System()
    self.event_names = events
    self.events = []
    self.fds = []
    for e in events:
      err, encoding = pfm_get_perf_event_encoding(e, PFM_PLM0 | PFM_PLM3,
                                                  None, None)
      self.events.append(encoding)

  def __del__(self):
    pass

  def read(self, fd):
    # TODO: determine counter width
    return os.read(fd, 8)

class SystemWideSession(Session):
  def __init__(self, cpus, events):
    self.cpus = cpus
    Session.__init__(self, events)

  def __del__(self):
    Session.__del__(self)

  def start(self):
    self.cpu_fds = []
    for c in self.cpus:
      self.cpu_fds.append([])
      cur_cpu_fds = self.cpu_fds[-1]
      for e in self.events:
        cur_cpu_fds.append(perf_event_open(e, -1, c, -1, 0))

  def read(self, c, i):
    index = self.cpus.index(c)
    return Session.read(self, self.cpu_fds[index][i])

class PerThreadSession(Session):
  def __init__(self, pid, events):
    self.pid = pid
    Session.__init__(self, events)

  def __del__(self):
    Session.__del__(self)

  def start(self):
    for e in self.events:
      self.fds.append(perf_event_open(e, self.pid, -1, -1, 0))

  def read(self, i):
    return Session.read(self, self.fds[i])
