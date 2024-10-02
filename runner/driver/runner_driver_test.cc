// Copyright 2022 The SiliFuzz Authors.
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

#include "./runner/driver/runner_driver.h"

#include <sys/types.h>
#include <sys/user.h>

#include <cstdint>
#include <filesystem>  // NOLINT

#include "gtest/gtest.h"
#include "absl/status/statusor.h"
#include "./common/harness_tracer.h"
#include "./common/proxy_config.h"
#include "./common/snapshot.h"
#include "./common/snapshot_enums.h"
#include "./common/snapshot_test_enum.h"
#include "./runner/runner_provider.h"
#include "./snap/testing/snap_test_snapshots.h"
#include "./util/arch.h"
#include "./util/data_dependency.h"
#include "./util/itoa.h"
#include "./util/path_util.h"
#include "./util/testing/status_macros.h"
#include "./util/ucontext/serialize.h"
#include "./util/ucontext/ucontext_types.h"

namespace silifuzz {
namespace {
using snapshot_types::PlaybackOutcome;

RunnerDriver HelperDriver() {
  return RunnerDriver::ReadingRunner(
      RunnerLocation(), GetDataDependencyFilepath("snap/testing/test_corpus"));
}

TEST(RunnerDriver, BasicRun) {
  RunnerDriver driver = HelperDriver();
  auto run_result = driver.PlayOne(EnumStr(TestSnapshot::kEndsAsExpected));
  ASSERT_TRUE(run_result.success());
  // Check the rusage looks somewhat reasonable.
  EXPECT_GE(run_result.rusage().ru_maxrss, 4);
}

TEST(RunnerDriver, BasicMake) {
  RunnerDriver driver = HelperDriver();
  auto make_result = driver.MakeOne(EnumStr(TestSnapshot::kSigSegvRead));
  ASSERT_FALSE(make_result.success());
  ASSERT_EQ(make_result.failed_player_result().outcome,
            PlaybackOutcome::kExecutionMisbehave);
  ASSERT_EQ(make_result.failed_snapshot_id(),
            EnumStr(TestSnapshot::kSigSegvRead));
}

TEST(RunnerDriver, MaxPageToAddOption) {
  RunnerDriver driver = HelperDriver();
  auto make_result = driver.MakeOne(EnumStr(TestSnapshot::kSigSegvReadFixable),
                                    /*max_pages_to_add=*/0);
  ASSERT_FALSE(make_result.success());
  ASSERT_EQ(make_result.failed_player_result().outcome,
            PlaybackOutcome::kExecutionMisbehave);
  ASSERT_EQ(make_result.failed_snapshot_id(),
            EnumStr(TestSnapshot::kSigSegvReadFixable));

  // Make again with runner adding pages automatically.
  make_result = driver.MakeOne(EnumStr(TestSnapshot::kSigSegvReadFixable),
                               /*max_pages_to_add=*/1);
  ASSERT_FALSE(make_result.success());
  // The snapshot should complete with a register mismatch instead of
  // a SEGV fault.
  ASSERT_EQ(make_result.failed_player_result().outcome,
            PlaybackOutcome::kRegisterStateMismatch);
  ASSERT_EQ(make_result.failed_snapshot_id(),
            EnumStr(TestSnapshot::kSigSegvReadFixable));

  ASSERT_TRUE(make_result.failed_player_result().actual_end_state.has_value());
  Snapshot::EndState end_state =
      make_result.failed_player_result().actual_end_state.value();

  // We should find memory bytes not in the original memory mapping.
  Snapshot snapshot =
      MakeSnapRunnerTestSnapshot<Host>(TestSnapshot::kSigSegvReadFixable);
  bool found_new_memory_bytes = false;
  for (const auto& memory_bytes : end_state.memory_bytes()) {
    if (!snapshot.mapped_memory_map().Contains(memory_bytes.start_address(),
                                               memory_bytes.limit_address())) {
      // We expect only one data page at start of data1 to be added.
      EXPECT_EQ(memory_bytes.start_address(),
                DEFAULT_FUZZING_CONFIG<Host>.data1_range.start_address);
      EXPECT_EQ(memory_bytes.num_bytes(), snapshot.page_size());
      found_new_memory_bytes = true;
    }
  }
  EXPECT_TRUE(found_new_memory_bytes);
}

TEST(RunnerDriver, BasicTrace) {
  RunnerDriver driver = HelperDriver();
  Snapshot endAsExpectedSnap =
      MakeSnapRunnerTestSnapshot<Host>(TestSnapshot::kEndsAsExpected);
  GRegSet<Host> gregs;
  ASSERT_TRUE(DeserializeGRegs(endAsExpectedSnap.registers().gregs(), &gregs));
  const uint64_t start_address = gregs.GetInstructionPointer();
  bool hit_initial_snap_rip = false;
  auto cb = [&hit_initial_snap_rip, start_address](
                pid_t pid, const user_regs_struct& regs,
                HarnessTracer::CallbackReason reason) {
    if (GetInstructionPointer(regs) == start_address) {
      hit_initial_snap_rip = true;
      return HarnessTracer::kStopTracing;
    }
    return HarnessTracer::kKeepTracing;
  };
  auto trace_result_or =
      driver.TraceOne(EnumStr(TestSnapshot::kEndsAsExpected), cb);
  ASSERT_TRUE(trace_result_or.success());
  ASSERT_TRUE(hit_initial_snap_rip);
  // Check the rusage looks somewhat reasonable.
  EXPECT_GE(trace_result_or.rusage().ru_maxrss, 4);
}

TEST(RunnerDriver, Cleanup) {
  auto tmp_binary = CreateTempFile("binary");
  ASSERT_OK(tmp_binary);
  ASSERT_TRUE(std::filesystem::exists(*tmp_binary));
  bool file_removed = false;
  {
    RunnerDriver driver = RunnerDriver::ReadingRunner(
        *tmp_binary, "<bogus>", "<bogus>",
        [&] { file_removed = std::filesystem::remove(*tmp_binary); });
  }
  ASSERT_TRUE(file_removed);
  ASSERT_FALSE(std::filesystem::exists(*tmp_binary));
}

}  // namespace
}  // namespace silifuzz
