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

#include "./proxies/pmu_event_proxy/perf_event_buffer.h"

#include <linux/hw_breakpoint.h> /* Definition of HW_* constants */
#include <linux/perf_event.h>
#include <sys/select.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <thread>  // NOLINT(build/c++11)
#include <utility>
#include <vector>

#include "gtest/gtest.h"
#include "absl/log/log.h"
#include "absl/random/distributions.h"
#include "absl/random/random.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/synchronization/notification.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "./proxies/pmu_event_proxy/perf_event_records.h"
#include "./util/cpu_id.h"
#include "./util/testing/status_macros.h"
#include "perfmon/pfmlib.h"
#include "perfmon/pfmlib_perf_event.h"
namespace silifuzz {
namespace {

void BindToARandomCPU() {
  std::vector<int> cpus;
  ForEachAvailableCPU([&](int cpu) { cpus.push_back(cpu); });
  if (cpus.empty()) {
    LOG(ERROR) << "No CPU found";
    return;
  }
  size_t index = absl::Uniform<size_t>(absl::BitGen(), 0, cpus.size());
  int cpu = cpus[index];
  if (SetCPUAffinity(cpu) != 0) {
    LOG(ERROR) << "SetCPUAffinity failed: " << strerror(errno);
  }
}

TEST(PerfEventBuffer, BasicTest) {
  constexpr uint64_t kSampleType = PERF_SAMPLE_READ;
  constexpr uint64_t kReadFormat = 0;

  // We will set a write breakpoint here.
  volatile char dummy;

  struct perf_event_attr attr {
    .type = PERF_TYPE_BREAKPOINT, .size = sizeof(perf_event_attr),
    // Generate a sample everytime the breakpoint is triggered.
        .sample_period = 1, .sample_type = kSampleType,
    .read_format = kReadFormat, .pinned = 1, .exclude_kernel = 1,
    .exclude_hv = 1, .bp_type = HW_BREAKPOINT_W,
    .bp_addr = reinterpret_cast<uintptr_t>(&dummy),
    .bp_len = HW_BREAKPOINT_LEN_1,
  };
  // Open a perf event file descriptor for this thread on any CPU.
  int fd = perf_event_open(&attr, /*pid=*/0, /*cpu=*/-1, /*group_fd=*/-1,
                           /*flags=*/0);
  ASSERT_NE(fd, -1) << "perf_event_attr failed: " << strerror(errno);

  // Use a small buffer to test ring buffer wrapping.
  const size_t kBufferSize = getpagesize();
  absl::StatusOr<std::unique_ptr<PerfEventBuffer>> event_buffer =
      PerfEventBuffer::Create(fd, kBufferSize, /*sample_type=*/kSampleType,
                              /*read_format=*/kReadFormat);
  ASSERT_OK(event_buffer.status());

  // Generate perf event sample record by triggering the data breakpoint.
  constexpr size_t kNumEvents = 4;
  for (size_t i = 0; i < kNumEvents; ++i) {
    // This will generate a data breakpoint event.
    dummy = 0;
  }

  for (size_t i = 0; i < kNumEvents; ++i) {
    absl::StatusOr<perf_event_type> event_type =
        event_buffer.value()->NextEventType();
    ASSERT_OK(event_type.status());
    ASSERT_EQ(event_type.value(), PERF_RECORD_SAMPLE);
    absl::StatusOr<PerfEventSampleRecord> sample_record =
        event_buffer.value()->ReadSampleRecord();
    ASSERT_OK(sample_record.status());

    // We should get how many times the breakpoint was triggered.
    ASSERT_EQ(sample_record.value().v().nr(), 1);
    EXPECT_EQ(sample_record.value().v().value(0), i + 1);
  }
  // Disable counter just to be safe.
  EXPECT_EQ(ioctl(fd, PERF_EVENT_IOC_DISABLE), 0);

  EXPECT_OK(PerfEventBuffer::Destroy(std::move(event_buffer.value())));
  EXPECT_EQ(close(fd), 0) << "close() failed: " << strerror(errno);
}

// This is similar to the basic test except that we create a separate thread to
// generate perf events. To test memory ordering, the generator thread is bound
// to a random CPU so there is likely to be cross-core memory traffic.
TEST(PerfEventBuffer, MultiThreaded) {
  // Each record is 16-bytes, do this many events so that
  // event buffer wraps around at least once.
  const size_t page_size = getpagesize();
  constexpr size_t kSampleRecordSize = 16;
  const size_t num_events = (page_size / kSampleRecordSize) + 20;

  // We will set a write breakpoint here for the event generator thread.
  volatile char dummy;

  // The event generator writes it TID at start up and notify the main thread
  // that the TID is valid for use in perf_event_open().
  absl::Notification event_generator_tid_valid;
  pid_t event_generator_tid;

  // The event generator blocks after writing its TID. The main thread unblocks
  // the generator after it has set up perf event monitoring.
  absl::Notification can_generate_events;

  std::thread event_generator_thread(
      [&event_generator_tid, &event_generator_tid_valid, &can_generate_events,
       num_events, &dummy]() {
        // Notify main thread that TID is valid.
        event_generator_tid = syscall(SYS_gettid);
        event_generator_tid_valid.Notify();

        BindToARandomCPU();

        // Wait until perf event monitoring is set up.
        can_generate_events.WaitForNotification();

        for (size_t i = 0; i < num_events; ++i) {
          // This will generate a data breakpoint event:
          //
          // The main thread sets a data breakpoint for this thread at &dummy.
          // The write below to dummy to triggers a data breakpoint event,
          // which will be recorded by kernel and placed in the perf event
          // buffer.
          dummy = 0;

          // Add a 1ms delay so that reader can keep up. Otherwise, the kernel
          // could generate a sample lost event, which we do not know how to
          // parse and handle yet.
          absl::SleepFor(absl::Milliseconds(1));
        }
      });

  // Wait until generator TID is valid.
  event_generator_tid_valid.WaitForNotification();

  // Create a data breakpoint event in generator thread on any CPU.
  constexpr uint64_t kSampleType = PERF_SAMPLE_READ;
  constexpr uint64_t kReadFormat = 0;
  struct perf_event_attr attr {
    .type = PERF_TYPE_BREAKPOINT, .size = sizeof(perf_event_attr),
    // Generate a sample everytime the breakpoint is triggered.
        .sample_period = 1, .sample_type = kSampleType,
    .read_format = kReadFormat, .pinned = 1, .exclude_kernel = 1,
    .exclude_hv = 1, .wakeup_events = 1, .bp_type = HW_BREAKPOINT_W,
    .bp_addr = reinterpret_cast<uintptr_t>(&dummy),
    .bp_len = HW_BREAKPOINT_LEN_1,
  };
  int fd =
      perf_event_open(&attr, event_generator_tid, /*cpu=*/-1, /*group_fd=*/-1,
                      /*flags=*/0);
  ASSERT_NE(fd, -1) << "perf_event_open() failed: " << strerror(errno);

  // Set up a event buffer.
  const size_t kBufferSize = getpagesize();
  absl::StatusOr<std::unique_ptr<PerfEventBuffer>> event_buffer =
      PerfEventBuffer::Create(fd, kBufferSize, /*sample_type=*/kSampleType,
                              /*read_format=*/kReadFormat);
  ASSERT_OK(event_buffer.status());

  // Unblock generator after we have set up perf event.
  can_generate_events.Notify();

  // Read perf event records generated by breakpoint events.
  fd_set event_fd_set;
  FD_ZERO(&event_fd_set);
  FD_SET(fd, &event_fd_set);
  size_t record_count = 0;
  // Total timeout for all records.
  constexpr absl::Duration kTimeout = absl::Seconds(30);
  timeval timeout = absl::ToTimeval(kTimeout);
  while (record_count < num_events) {
    absl::StatusOr<perf_event_type> event_type =
        event_buffer.value()->NextEventType();
    // If there data not available, block until we have some.
    if (absl::IsOutOfRange(event_type.status())) {
      // Check that we have not used up total timeout.
      ASSERT_GT(absl::DurationFromTimeval(timeout), absl::ZeroDuration());
      int select_result =
          select(fd + 1, &event_fd_set, nullptr, nullptr, &timeout);
      if (select_result == -1 && errno == EINTR) continue;
      ASSERT_NE(select_result, -1) << "select() failed: " << strerror(errno);
      continue;
    }
    ASSERT_OK(event_type.status());
    ASSERT_EQ(event_type.value(), PERF_RECORD_SAMPLE);
    absl::StatusOr<PerfEventSampleRecord> sample_record =
        event_buffer.value()->ReadSampleRecord();
    ASSERT_OK(sample_record.status());

    // We should get how many times the breakpoint was triggered.
    record_count++;
    ASSERT_EQ(sample_record.value().v().nr(), 1);
    EXPECT_EQ(sample_record.value().v().value(0), record_count);
  }

  // Disable counter just to be safe.
  EXPECT_EQ(ioctl(fd, PERF_EVENT_IOC_DISABLE), 0);

  // Dispose of perf event file descriptor and event buffer.
  EXPECT_OK(PerfEventBuffer::Destroy(std::move(event_buffer.value())));
  EXPECT_EQ(close(fd), 0) << "close() failed: " << strerror(errno);

  event_generator_thread.join();
}

// Test that perf event buffer releases all resources at destruction.
// Previously a bug in Create() caused debug registers not to be freed.
TEST(PerfEventBuffer, NoDebugRegisterLeak) {
  // This should be larger than the number of debug registers available.
  // For x86 it is 4.
  constexpr size_t kIterations = 20;
  for (size_t i = 0; i < kIterations; ++i) {
    // We will create a write breakpoint to it. For this test it is sufficient
    // to just create a breakpoint. The breakpoint is never triggered.
    static const char* kData = "Hello";
    perf_event_attr attr = {
        .type = PERF_TYPE_BREAKPOINT,
        .size = sizeof(perf_event_attr),
        .sample_period = 1,
        .exclude_kernel = 1,
        .exclude_hv = 1,
        .bp_type = HW_BREAKPOINT_W,
        .bp_addr = reinterpret_cast<uintptr_t>(&kData),
        .bp_len = HW_BREAKPOINT_LEN_1,
    };
    const int fd =
        perf_event_open(&attr, /*pid=*/0, /*cpu=*/-1, /*group_fd=*/-1,
                        /*flags=*/0);
    ASSERT_NE(fd, -1) << "perf_event_open() failed: " << strerror(errno);
    ASSERT_OK_AND_ASSIGN(std::unique_ptr<PerfEventBuffer> event_buffer,
                         PerfEventBuffer::Create(fd, getpagesize(), 0, 0));
    // If this does not unmap the buffer completely, the debug register
    // associated with the perf event will not be freed even if the perf
    // event descriptor is closed. This will cause subsequent calls to
    // perf_event_open() fail when all debug registers have been exhausted.
    EXPECT_OK(PerfEventBuffer::Destroy(std::move(event_buffer)));
    EXPECT_EQ(close(fd), 0) << "close() failed: " << strerror(errno);
  }
}

}  // namespace
}  // namespace silifuzz
