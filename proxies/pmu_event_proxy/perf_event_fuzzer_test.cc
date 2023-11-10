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

#include "./proxies/pmu_event_proxy/perf_event_fuzzer.h"

#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "./common/harness_tracer.h"
#include "./common/snapshot.h"
#include "./common/snapshot_test_config.h"
#include "./common/snapshot_test_enum.h"
#include "./common/snapshot_test_util.h"
#include "./proxies/pmu_event_proxy/perf_event_buffer.h"
#include "./runner/driver/runner_driver.h"
#include "./runner/runner_provider.h"
#include "./runner/snap_maker.h"
#include "./util/arch.h"
#include "./util/checks.h"
#include "./util/testing/status_macros.h"
#include "./util/testing/status_matchers.h"
#include "external/libpfm4/include/perfmon/pfmlib.h"
#include "external/libpfm4/include/perfmon/pfmlib_perf_event.h"

using ::silifuzz::testing::IsOk;
using ::silifuzz::testing::IsOkAndHolds;
using ::silifuzz::testing::StatusIs;
using ::testing::Eq;
using ::testing::Gt;
using ::testing::IsEmpty;
using ::testing::IsTrue;
using ::testing::Le;
using ::testing::Not;
using ::testing::NotNull;
using ::testing::SizeIs;

namespace silifuzz {
namespace {

class Environment : public ::testing::Environment {
 public:
  ~Environment() override {}

  void SetUp() override { CHECK_EQ(pfm_initialize(), PFM_SUCCESS); }

  void TearDown() override {}
};

::testing::Environment* const test_env =
    ::testing::AddGlobalTestEnvironment(new Environment);

TEST(PerfEventMeasurement, BasicTest) {
  std::vector<uint64_t> counts = {1, 2, 3};
  constexpr absl::string_view kEvent = "event";

  PerfEventMeasurements m1(kEvent, counts);
  EXPECT_EQ(m1.event(), kEvent);
  EXPECT_EQ(m1.counts(), counts);
  ASSERT_TRUE(m1.mean().has_value());
  EXPECT_FLOAT_EQ(m1.mean().value(), 2.0);
  ASSERT_TRUE(m1.stddev().has_value());
  EXPECT_FLOAT_EQ(m1.stddev().value(), 1.0);

  std::vector<uint64_t> counts2(counts);
  PerfEventMeasurements m2(kEvent, std::move(counts2));
  EXPECT_EQ(m1, m2);

  // Test empty counts
  PerfEventMeasurements m3("empty", {});
  ASSERT_FALSE(m3.mean().has_value());
  ASSERT_FALSE(m3.stddev().has_value());

  // Test single-ton counts.
  PerfEventMeasurements m4(kEvent, {1});
  ASSERT_TRUE(m4.mean().has_value());
  EXPECT_FLOAT_EQ(m4.mean().value(), 1.0);
  ASSERT_FALSE(m4.stddev().has_value());

  // Test copying constructors.
  PerfEventMeasurements m5(m1);
  EXPECT_EQ(m5, m1);
  m5 = m3;
  EXPECT_EQ(m5, m3);

  // Test moving constructors.
  PerfEventMeasurements m6("event", {1, 2, 3, 4, 5});
  PerfEventMeasurements m7(m6);
  PerfEventMeasurements m8;
  EXPECT_NE(m6, m8);
  m8 = std::move(m7);
  EXPECT_EQ(m6, m8);
  PerfEventMeasurements m9(std::move(m8));
  EXPECT_EQ(m9, m6);
}

TEST(PerfEventGroup, BasicTest) {
  // We set a data breakpoint to here.  The breakpoint is not triggered in this
  // test.
  volatile char dummy;
  constexpr uint64_t kSampleType = PERF_SAMPLE_READ;
  constexpr uint64_t kReadFormat = PERF_FORMAT_GROUP | PERF_FORMAT_ID;
  struct perf_event_attr attr {
    .type = PERF_TYPE_BREAKPOINT, .size = sizeof(perf_event_attr),
    // Generate a sample everytime the leader event happens.
        .sample_period = 1, .sample_type = kSampleType,
    .read_format = kReadFormat, .pinned = 1, .exclude_kernel = 1,
    .exclude_hv = 1, .exclude_idle = 1,
    // The leader event is a data breakpoint.  It triggers whenever this
    // magic address is written.
        .bp_type = HW_BREAKPOINT_W,
    .bp_addr = reinterpret_cast<uintptr_t>(&dummy),
    .bp_len = HW_BREAKPOINT_LEN_1,
  };

  // Create a perf event group lead by a data breakpoint.
  pid_t tid = syscall(SYS_gettid);
  constexpr absl::string_view kLeaderEvent = "breakpoint";
  absl::StatusOr<std::unique_ptr<PerfEventGroup>> group =
      PerfEventGroup::Create(kLeaderEvent, &attr, tid);
  ASSERT_OK(group);

  EXPECT_EQ(group.value()->size(), 1);
  const PerfEventGroup::PerfEventDescriptor& leader_event =
      group.value()->event(0);
  EXPECT_EQ(leader_event.event, kLeaderEvent);
  EXPECT_GE(leader_event.fd, 0);
  uint64_t id = 0;
  EXPECT_EQ(ioctl(leader_event.fd, PERF_EVENT_IOC_ID, &id), 0);
  EXPECT_EQ(leader_event.id, id);

  // Add a software event, that is platform independent. This
  // should be available under all circumstances. Hardware
  // counters may not be always available in testing environment.
  constexpr absl::string_view kSWCPUClock = "PERF_COUNT_SW_CPU_CLOCK";
  EXPECT_OK(group.value()->AddPerfEvent("PERF_COUNT_SW_CPU_CLOCK"));
  EXPECT_EQ(group.value()->size(), 2);
  const PerfEventGroup::PerfEventDescriptor& sw_cpu_clock_event =
      group.value()->event(1);
  EXPECT_EQ(sw_cpu_clock_event.event, kSWCPUClock);
  EXPECT_GE(sw_cpu_clock_event.fd, 0);
  EXPECT_EQ(ioctl(sw_cpu_clock_event.fd, PERF_EVENT_IOC_ID, &id), 0);
  EXPECT_EQ(sw_cpu_clock_event.id, id);

  // Check closing events.
  EXPECT_OK(PerfEventGroup::Destroy(std::move(group.value())));
}

TEST(PerfEventFuzzer, BasicTest) {
  PerfEventFuzzer::EventList events{
      // Common hardware counters that should be available on most platforms.
      "PERF_COUNT_HW_CPU_CYCLES",
      "PERF_COUNT_HW_INSTRUCTIONS",
      "PERF_COUNT_HW_CACHE_MISSES",
      "PERF_COUNT_HW_BRANCH_INSTRUCTIONS",
  };

  const std::string ends_as_expected =
      GetTestSnippet<Host>(TestSnapshot::kEndsAsExpected);

  PerfEventFuzzer::Options options = PerfEventFuzzer::Options::Default();
  // We cannot handle generic PMU event scheduling.
  options.schedule_events = false;
  PerfEventFuzzer fuzzer(events, options);
  constexpr size_t kIterations = 10;
  size_t non_zero_measurements = 0;
  ASSERT_OK_AND_ASSIGN(
      PerfEventFuzzer::PerfEventMeasurementList measurement_list,
      fuzzer.FuzzOneInput(
          reinterpret_cast<const uint8_t*>(ends_as_expected.data()),
          ends_as_expected.size(), kIterations));
  EXPECT_THAT(measurement_list, SizeIs(Eq(events.size())));
  for (size_t i = 0; i < events.size(); ++i) {
    const PerfEventMeasurements& measurements = measurement_list[i];
    EXPECT_EQ(measurements.event(), events[i]);
    ASSERT_THAT(measurements.counts(), Not(IsEmpty()));
    EXPECT_THAT(measurements.counts(), SizeIs(Le(kIterations)));
    // We run 10 iterations, it is unlikely that we do not have any values.
    ASSERT_THAT(measurements.mean().has_value(), IsTrue());
    if (measurements.mean().value() > 0.0) {
      non_zero_measurements++;
    }
  }
  EXPECT_THAT(non_zero_measurements, Gt(0));
}

// This test verifies that the harness tracer callback is only called twice per
// snapshot execution when single-stepping is not done. The perf event fuzzer
// makes this assumption.
TEST(PerfEventFuzzer, CallbackCalledOnlyTwice) {
  const std::string runner_path = RunnerLocation();
  SnapMaker snap_maker(SnapMaker::Options{.runner_path = runner_path});

  Snapshot snapshot = CreateTestSnapshot<Host>(TestSnapshot::kEndsAsExpected);
  ASSERT_OK_AND_ASSIGN(snapshot, snap_maker.Make(snapshot));
  ASSERT_OK_AND_ASSIGN(snapshot, snap_maker.RecordEndState(snapshot));
  ASSERT_OK_AND_ASSIGN(RunnerDriver runner_driver,
                       RunnerDriverFromSnapshot(snapshot, runner_path));

  // We are going to set a breakpoint at snapshot entrance.
  uint64_t start_address = snapshot.ExtractRip(snapshot.registers());
  constexpr uint64_t kReadFormat = PERF_FORMAT_GROUP;
  struct perf_event_attr attr {
    .type = PERF_TYPE_BREAKPOINT, .size = sizeof(perf_event_attr),
    .sample_period = 1, .read_format = kReadFormat, .exclude_kernel = 1,
    .exclude_hv = 1, .exclude_idle = 1, .bp_type = HW_BREAKPOINT_X,
    .bp_addr = start_address,
    .bp_len = sizeof(long),  // NOLINT
  };

  size_t callback_count = 0;
  absl::StatusOr<std::unique_ptr<PerfEventGroup>> perf_event_group;
  absl::StatusOr<std::unique_ptr<PerfEventBuffer>> perf_event_buffer;
  auto harness_tracer_callback = [&callback_count, &attr, &perf_event_group,
                                  &perf_event_buffer](
                                     pid_t pid, const user_regs_struct& regs,
                                     HarnessTracer::CallbackReason reason) {
    // Set up perf event monitoring at the first call.
    if (callback_count == 0) {
      perf_event_group = PerfEventGroup::Create("breakpoint", &attr, pid);
      if (perf_event_group.ok()) {
        const size_t kBufferSize = getpagesize();
        perf_event_buffer = PerfEventBuffer::Create(
            perf_event_group.value()->event(0).fd, kBufferSize, 0, kReadFormat);
      }
    }
    callback_count++;

    // We are not single-stepping. Inform harness tracer to stop tracing.
    return HarnessTracer::kStopTracing;
  };
  absl::StatusOr<RunnerDriver::RunResult> run_result =
      runner_driver.TraceOne(snapshot.id(), harness_tracer_callback);
  EXPECT_THAT(run_result.status(), IsOk());

  ASSERT_THAT(perf_event_group, IsOkAndHolds(NotNull()));
  ASSERT_THAT(perf_event_buffer, IsOkAndHolds(NotNull()));
  EXPECT_THAT(callback_count, Eq(2));

  // There should be only one record.
  EXPECT_THAT(perf_event_buffer.value()->NextEventType(),
              IsOkAndHolds(Eq(PERF_RECORD_SAMPLE)));
  EXPECT_THAT(perf_event_buffer.value()->ReadSampleRecord(), IsOk());
  EXPECT_THAT(perf_event_buffer.value()->NextEventType(),
              StatusIs(absl::StatusCode::kOutOfRange));

  EXPECT_THAT(PerfEventBuffer::Destroy(std::move(perf_event_buffer.value())),
              IsOk());
  EXPECT_THAT(PerfEventGroup::Destroy(std::move(perf_event_group.value())),
              IsOk());
}

// Runaway input should not crash the fuzzer.
TEST(PerfEventFuzzer, RejectMisbehavingInput) {
  PerfEventFuzzer::EventList events{
      // Common hardware counters that should be available on most platforms.
      "PERF_COUNT_HW_CPU_CYCLES",
      "PERF_COUNT_HW_INSTRUCTIONS",
      "PERF_COUNT_HW_CACHE_MISSES",
      "PERF_COUNT_HW_BRANCH_INSTRUCTIONS",
  };

  const std::string run_away = GetTestSnippet<Host>(TestSnapshot::kRunaway);
  PerfEventFuzzer::Options options = PerfEventFuzzer::Options::Default();
  // We cannot handle generic PMU event scheduling.
  options.schedule_events = false;
  PerfEventFuzzer fuzzer(events, options);
  constexpr size_t kIterations = 10;
  // We should get an error instead of crashing the fuzzer.
  EXPECT_THAT(
      fuzzer.FuzzOneInput(reinterpret_cast<const uint8_t*>(run_away.data()),
                          run_away.size(), kIterations),
      StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace silifuzz
