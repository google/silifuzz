// Copyright 2023 The SiliFuzz Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "./proxies/pmu_event_proxy/pmu_events.h"

#include <linux/hw_breakpoint.h> /* Definition of HW_* constants */
#include <linux/perf_event.h>    /* Definition of PERF_* constants */
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstring>

#include "gtest/gtest.h"
#include "absl/log/log.h"
#include "./util/testing/status_macros.h"
#include "perfmon/pfmlib.h"
#include "perfmon/pfmlib_perf_event.h"

namespace silifuzz {
namespace {

// We will set a dummy data breakpoint here as an event group leader.
char dummy = 0;

TEST(PMUEvents, CanOpenAllEvents) {
  auto events = GetUniqueFilteredCPUCorePMUEvents();
  LOG(INFO) << "Found " << events.value().size() << " events";
  ASSERT_OK(events);
  size_t opened_counters = 0;
  for (const auto& event : events.value()) {
    perf_event_attr attr{
        .size = sizeof(perf_event_attr),
    };
    pfm_perf_encode_arg_t arg{
        .attr = &attr,
        .fstr = nullptr,
        .size = sizeof(pfm_perf_encode_arg_t),
    };
    ASSERT_EQ(pfm_get_os_event_encoding(event.c_str(), PFM_PLM3,
                                        PFM_OS_PERF_EVENT, &arg),
              PFM_SUCCESS);
    attr.sample_period = 10000;
    attr.pinned = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    const int fd = perf_event_open(&attr, 0 /* this process */, -1, -1, 0);
    opened_counters += fd != -1 ? 1 : 0;
    // Treat EACCES an acceptable result as the kernel may restrict
    // access to the events.
    EXPECT_TRUE(fd != -1 || errno == EACCES)
        << "Unexpected failure when opening event " << event << " :"
        << strerror(errno);
    if (fd != -1) {
      EXPECT_NE(close(fd), -1);
    }
  }
  EXPECT_GT(opened_counters, 0);
}

TEST(PMUEvents, ScheduleEventsForCounters) {
  auto events = GetUniqueFilteredCPUCorePMUEvents();
  ASSERT_OK(events);
  auto event_groups = ScheduleEventsForCounters(events.value());
  ASSERT_OK(event_groups);
  LOG(INFO) << "Found " << event_groups.value().size() << " event groups";

  for (const auto& event_group : event_groups.value()) {
    /* Open a breakpoint event as a group leader */
    struct perf_event_attr breakpoint_attr {
      .type = PERF_TYPE_BREAKPOINT, .size = sizeof(perf_event_attr),
      // Generate a sample everytime the leader event happens.
          .sample_period = 100, .sample_type = PERF_SAMPLE_IP,
      .read_format = PERF_FORMAT_GROUP, .pinned = 1, .exclude_kernel = 1,
      .exclude_hv = 1,
      // The leader event is a dummy data breakpoint. This is not triggered
      // it this test, which only tests that counters can be opened.
          .bp_type = HW_BREAKPOINT_W,
      .bp_addr = reinterpret_cast<uintptr_t>(&dummy),
      .bp_len = HW_BREAKPOINT_LEN_1,
    };
    const int leader_fd =
        perf_event_open(&breakpoint_attr, 0 /* this process */, -1, -1, 0);
    ASSERT_NE(leader_fd, -1)
        << "Unexpected failure when opening breakpoint event: "
        << strerror(errno);

    // Open all events in group.
    for (size_t i = 0; i < event_group.size(); ++i) {
      const auto& event = event_group[i];
      perf_event_attr attr{
          .size = sizeof(perf_event_attr),
      };
      pfm_perf_encode_arg_t arg{
          .attr = &attr,
          .fstr = nullptr,
          .size = sizeof(pfm_perf_encode_arg_t),
      };
      ASSERT_EQ(pfm_get_os_event_encoding(event.c_str(), PFM_PLM3,
                                          PFM_OS_PERF_EVENT, &arg),
                PFM_SUCCESS);
      const int fd =
          perf_event_open(&attr, 0 /* this process */, -1, leader_fd, 0);
      // Treat EACCES an acceptable result as the kernel may restrict
      // access to the events.
      EXPECT_TRUE(fd != -1 || errno == EACCES)
          << "Unexpected failure when opening event " << event << " (" << i
          << " of " << event_group.size() << "): " << strerror(errno);
      if (fd != -1) {
        EXPECT_NE(close(fd), -1);
      }
    }
    close(leader_fd);
  }
}

}  // namespace
}  // namespace silifuzz
