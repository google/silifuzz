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

#include <fcntl.h>
#include <unistd.h>

#include <cstdint>
#include <optional>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "./common/snapshot_enums.h"
#include "./runner/driver/runner_driver.h"
#include "./runner/runner_provider.h"
#include "./snap/gen/relocatable_snap_generator.h"
#include "./snap/testing/snap_test_snaps.h"
#include "./util/file_util.h"
#include "./util/path_util.h"
#include "./util/testing/status_macros.h"
#include "./util/testing/status_matchers.h"
#include "./util/ucontext/ucontext.h"

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
    opts.set_wall_time_budget(timeout);
    opts.set_cpu_time_budget(timeout * 10);
  }
  return driver.Run(opts);
}

TEST(RunnerTest, AsExpectedSnap) {
  Snap asExpectedSnap = GetSnapRunnerTestSnap(TestSnapshot::kEndsAsExpected);
  ASSERT_OK_AND_ASSIGN(auto result, RunOneSnap(asExpectedSnap));
  ASSERT_TRUE(result.success());
}

TEST(RunnerTest, RegisterMismatchSnap) {
  Snap regsMismatchSnap = GetSnapRunnerTestSnap(TestSnapshot::kRegsMismatch);
  ASSERT_OK_AND_ASSIGN(auto result, RunOneSnap(regsMismatchSnap));
  ASSERT_FALSE(result.success());
  EXPECT_EQ(result.player_result().outcome,
            PlaybackOutcome::kRegisterStateMismatch);
}

TEST(RunnerTest, MemoryMismatchSnap) {
  Snap memoryMismatchSnap =
      GetSnapRunnerTestSnap(TestSnapshot::kMemoryMismatch);
  ASSERT_OK_AND_ASSIGN(auto result, RunOneSnap(memoryMismatchSnap));
  ASSERT_FALSE(result.success());
  EXPECT_EQ(result.player_result().outcome, PlaybackOutcome::kMemoryMismatch);
  const auto& end_state = *result.player_result().actual_end_state;
  EXPECT_THAT(end_state.memory_bytes(), Not(IsEmpty()));
  EXPECT_EQ(end_state.endpoint().instruction_address(),
            memoryMismatchSnap.end_state_instruction_address);
}

TEST(RunnerTest, SigSegvSnap) {
  Snap sigSegvReadSnap = GetSnapRunnerTestSnap(TestSnapshot::kSigSegvRead);
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
  const uint64_t start_address =
      GetInstructionPointer(sigSegvReadSnap.registers->gregs);
  EXPECT_EQ(ep.sig_instruction_address(), start_address + 4);
  EXPECT_EQ(ep.sig_address(), 0x1000000);
  EXPECT_EQ(ep.sig_num(), snapshot_types::SigNum::kSigSegv);
  EXPECT_EQ(ep.sig_cause(), snapshot_types::SigCause::kSegvCantRead);
}

TEST(RunnerTest, SyscallSnap) {
  Snap syscallSnap = GetSnapRunnerTestSnap(TestSnapshot::kSyscall);
  auto result = RunOneSnap(syscallSnap);
  ASSERT_THAT(result,
              StatusIs(absl::StatusCode::kInternal, HasSubstr("syscall")));
}

TEST(RunnerTest, BreakpointSnap) {
  Snap breakpointSnap = GetSnapRunnerTestSnap(TestSnapshot::kBreakpoint);
  ASSERT_OK_AND_ASSIGN(auto result, RunOneSnap(breakpointSnap));
  ASSERT_FALSE(result.success());
  EXPECT_EQ(result.player_result().outcome,
            PlaybackOutcome::kExecutionMisbehave);
  const snapshot_types::Endpoint& ep =
      result.player_result().actual_end_state->endpoint();
  const uint64_t start_address =
      GetInstructionPointer(breakpointSnap.registers->gregs);
  EXPECT_EQ(ep.sig_instruction_address(), start_address);
  // The docs say that si_addr should be set for SIGTRAP, but emperically
  // speaking it is not set on x86_64.
#if defined(__x86_64__)
  const uintptr_t kExpectedSigAddress = 0x0;
#else
  const uintptr_t kExpectedSigAddress = start_address;
#endif
  EXPECT_EQ(ep.sig_address(), kExpectedSigAddress);
  EXPECT_EQ(ep.sig_num(), snapshot_types::SigNum::kSigTrap);
}

TEST(RunnerTest, RunawaySnap) {
  Snap runawaySnap = GetSnapRunnerTestSnap(TestSnapshot::kRunaway);
  ASSERT_OK_AND_ASSIGN(auto result, RunOneSnap(runawaySnap));
  ASSERT_FALSE(result.success());
  EXPECT_EQ(result.player_result().outcome, PlaybackOutcome::kExecutionRunaway);
}

TEST(RunnerTest, Deadline) {
  Snap runawaySnap = GetSnapRunnerTestSnap(TestSnapshot::kRunaway);
  ASSERT_OK_AND_ASSIGN(auto result, RunOneSnap(runawaySnap, absl::Seconds(2)));
  ASSERT_TRUE(result.success());
}

TEST(RunnerTest, EmptyCorpus) {
  MmappedMemoryPtr<char> buffer =
      GenerateRelocatableSnaps(Host::architecture_id, {});
  ASSERT_OK_AND_ASSIGN(auto path, CreateTempFile("EmptyCorpus", ""));

  int fd = open(path.c_str(), O_WRONLY);
  ASSERT_NE(fd, -1);
  absl::string_view buf(buffer.get(), MmappedMemorySize(buffer));
  ASSERT_TRUE(WriteToFileDescriptor(fd, buf));
  close(fd);

  RunnerDriver driver = RunnerDriver::ReadingRunner(
      RunnerLocation(), path, [&path] { unlink(path.c_str()); });
  auto opts = RunnerOptions::Default();
  ASSERT_OK(driver.Run(opts));
  opts.set_sequential_mode(true);
  ASSERT_OK(driver.Run(opts));
}

TEST(RunnerTest, UnknownFlags) {
  RunnerDriver driver = RunnerDriver::BakedRunner(RunnerTestHelperLocation());
  Snap asExpectedSnap = GetSnapRunnerTestSnap(TestSnapshot::kEndsAsExpected);
  RunnerOptions opts = RunnerOptions::PlayOptions(asExpectedSnap.id);
  opts.set_extra_argv({"--foobar=1"});
  absl::StatusOr<RunnerDriver::RunResult> result = driver.Run(opts);
  ASSERT_THAT(result, StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace silifuzz
