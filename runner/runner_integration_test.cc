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

#include <cstdint>
#include <optional>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/time/time.h"
#include "./common/snapshot_enums.h"
#include "./runner/driver/runner_driver.h"
#include "./runner/runner_provider.h"
#include "./snap/testing/snap_test_snaps.h"
#include "./snap/testing/snap_test_types.h"
#include "./util/testing/status_macros.h"
#include "./util/testing/status_matchers.h"

namespace silifuzz {
namespace {

using ::silifuzz::testing::StatusIs;
using snapshot_types::PlaybackOutcome;
using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::Not;

// Runs the given `snap` and returns the execution result.
//
// NOTE: Assumes that the snap is already built into the test helper binary.
absl::StatusOr<RunnerDriver::RunResult> RunOneSnap(
    const Snap& snap, absl::Duration timeout = absl::InfiniteDuration()) {
  RunnerDriver driver = RunnerDriver::BakedRunner(RunnerTestHelperLocation());
  auto opts = RunnerOptions::PlayOptions(snap.id);
  if (timeout != absl::InfiniteDuration()) {
    opts.set_wall_time_bugdet(timeout);
    opts.set_cpu_time_bugdet(timeout * 10);
  }
  return driver.Run(opts);
}

// TODO(ksteuck): [test] Add tests for different snaps.
TEST(RunnerTest, MemoryMismatchSnap) {
  Snap memoryMismatchSnap =
      GetSnapRunnerTestSnap(SnapRunnerTestType::kMemoryMismatch);
  ASSERT_OK_AND_ASSIGN(auto result, RunOneSnap(memoryMismatchSnap));
  ASSERT_FALSE(result.success());
  EXPECT_EQ(result.player_result().outcome, PlaybackOutcome::kMemoryMismatch);
  const auto& end_state = *result.player_result().actual_end_state;
  EXPECT_THAT(end_state.memory_bytes(), Not(IsEmpty()));
  EXPECT_EQ(end_state.endpoint().instruction_address(),
            memoryMismatchSnap.end_state_instruction_address);
}

TEST(RunnerTest, SigSegvSnap) {
  Snap sigSegvReadSnap =
      GetSnapRunnerTestSnap(SnapRunnerTestType::kSigSegvRead);
  ASSERT_OK_AND_ASSIGN(auto result, RunOneSnap(sigSegvReadSnap));
  ASSERT_FALSE(result.success());
  EXPECT_EQ(result.player_result().outcome,
            PlaybackOutcome::kExecutionMisbehave);
  const Snapshot::EndState& end_state =
      *result.player_result().actual_end_state;
  EXPECT_THAT(end_state.memory_bytes(), Not(IsEmpty()));
  const snapshot_types::Endpoint& ep = end_state.endpoint();
  // The two magic addresses are snapshot-dependent but should be stable.
  // See TestSnapshots::Create() for the actual code sequence.
  const uint64_t start_address = sigSegvReadSnap.registers.gregs.rip;
  EXPECT_EQ(ep.sig_instruction_address(), start_address + 4);
  EXPECT_EQ(ep.sig_address(), 0x1000000);
  EXPECT_EQ(ep.sig_num(), snapshot_types::SigNum::kSigSegv);
  EXPECT_EQ(ep.sig_cause(), snapshot_types::SigCause::kSegvCantRead);
}

TEST(RunnerTest, SyscallSnap) {
  Snap syscallSnap = GetSnapRunnerTestSnap(SnapRunnerTestType::kSyscall);
  auto result = RunOneSnap(syscallSnap);
  ASSERT_THAT(result,
              StatusIs(absl::StatusCode::kInternal, HasSubstr("syscall")));
}

TEST(RunnerTest, INT3Snap) {
  Snap int3Snap = GetSnapRunnerTestSnap(SnapRunnerTestType::kINT3);
  ASSERT_OK_AND_ASSIGN(auto result, RunOneSnap(int3Snap));
  ASSERT_FALSE(result.success());
  EXPECT_EQ(result.player_result().outcome,
            PlaybackOutcome::kExecutionMisbehave);
  const snapshot_types::Endpoint& ep =
      result.player_result().actual_end_state->endpoint();
  // See TestSnapshots::Create() for the actual code sequence.
  const uint64_t start_address = int3Snap.registers.gregs.rip;
  EXPECT_EQ(ep.sig_instruction_address(), start_address);
  EXPECT_EQ(ep.sig_address(), 0x0);
  EXPECT_EQ(ep.sig_num(), snapshot_types::SigNum::kSigTrap);
}

TEST(RunnerTest, RunawaySnap) {
  Snap runawaySnap = GetSnapRunnerTestSnap(SnapRunnerTestType::kRunaway);
  ASSERT_OK_AND_ASSIGN(auto result, RunOneSnap(runawaySnap));
  ASSERT_FALSE(result.success());
  EXPECT_EQ(result.player_result().outcome, PlaybackOutcome::kExecutionRunaway);
}

TEST(RunnerTest, Deadline) {
  Snap runawaySnap = GetSnapRunnerTestSnap(SnapRunnerTestType::kRunaway);
  ASSERT_OK_AND_ASSIGN(auto result, RunOneSnap(runawaySnap, absl::Seconds(2)));
  ASSERT_TRUE(result.success());
}

}  // namespace
}  // namespace silifuzz
