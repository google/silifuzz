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
#include "./common/snapshot.h"
#include "./common/snapshot_enums.h"
#include "./common/snapshot_test_config.h"
#include "./common/snapshot_test_enum.h"
#include "./runner/driver/runner_driver.h"
#include "./runner/driver/runner_options.h"
#include "./runner/runner_provider.h"
#include "./snap/gen/relocatable_snap_generator.h"
#include "./snap/testing/snap_test_snapshots.h"
#include "./util/arch.h"
#include "./util/data_dependency.h"
#include "./util/file_util.h"
#include "./util/itoa.h"
#include "./util/mmapped_memory_ptr.h"
#include "./util/path_util.h"
#include "./util/testing/status_macros.h"
#include "./util/testing/status_matchers.h"
#include "./util/ucontext/serialize.h"
#include "./util/ucontext/ucontext_types.h"

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
    TestSnapshot test_snap_type,
    absl::Duration timeout = absl::InfiniteDuration()) {
  RunnerDriver driver = RunnerDriver::ReadingRunner(
      RunnerLocation(), GetDataDependencyFilepath("snap/testing/test_corpus"));
  RunnerOptions opts = RunnerOptions::PlayOptions(EnumStr(test_snap_type));
  if (timeout != absl::InfiniteDuration()) {
    opts.set_wall_time_budget(timeout);
    opts.set_cpu_time_budget(timeout * 10);
  }
  return driver.Run(opts);
}

TEST(RunnerTest, AsExpectedSnap) {
  ASSERT_OK_AND_ASSIGN(auto result, RunOneSnap(TestSnapshot::kEndsAsExpected));
  ASSERT_TRUE(result.success());
}

TEST(RunnerTest, RegisterMismatchSnap) {
  ASSERT_OK_AND_ASSIGN(auto result, RunOneSnap(TestSnapshot::kRegsMismatch));
  ASSERT_FALSE(result.success());
  EXPECT_EQ(result.player_result().outcome,
            PlaybackOutcome::kRegisterStateMismatch);
}

TEST(RunnerTest, MemoryMismatchSnap) {
  ASSERT_OK_AND_ASSIGN(auto result, RunOneSnap(TestSnapshot::kMemoryMismatch));
  ASSERT_FALSE(result.success());
  EXPECT_EQ(result.player_result().outcome, PlaybackOutcome::kMemoryMismatch);
  const auto& end_state = *result.player_result().actual_end_state;
  EXPECT_THAT(end_state.memory_bytes(), Not(IsEmpty()));

  Snapshot memoryMismatchSnap =
      MakeSnapRunnerTestSnapshot<Host>(TestSnapshot::kMemoryMismatch);
  EXPECT_EQ(end_state.endpoint().instruction_address(),
            memoryMismatchSnap.expected_end_states()[0]
                .endpoint()
                .instruction_address());
}

TEST(RunnerTest, SigSegvSnap) {
  ASSERT_OK_AND_ASSIGN(auto result,
                       RunOneSnap(TestSnapshot::kSigSegvReadFixable));
  ASSERT_FALSE(result.success());
  EXPECT_EQ(result.player_result().outcome,
            PlaybackOutcome::kExecutionMisbehave);
  const Snapshot::EndState& end_state =
      *result.player_result().actual_end_state;
  EXPECT_THAT(end_state.memory_bytes(), Not(IsEmpty()));
  const snapshot_types::Endpoint& ep = end_state.endpoint();
  // sig_address and sig_instruction_address addresses are snapshot-dependent
  // but should be stable. See TestSnapshot::kSigSegvRead in
  // snapshot_test_config.cc for the actual code sequence.
  const uint64_t start_address =
      GetTestSnapshotConfig<Host>(TestSnapshot::kSigSegvReadFixable)->code_addr;
  // The exact location of the faulting instruction depends on the arch.
  // Check that the PC is close to the start of the code page.
  EXPECT_GT(ep.sig_instruction_address(), start_address);
  EXPECT_LT(ep.sig_instruction_address(), start_address + 15);
  EXPECT_EQ(ep.sig_address(), 0x10000);
  EXPECT_EQ(ep.sig_num(), snapshot_types::SigNum::kSigSegv);
  EXPECT_EQ(ep.sig_cause(), snapshot_types::SigCause::kSegvCantRead);
}

TEST(RunnerTest, SyscallSnap) {
  auto result = RunOneSnap(TestSnapshot::kSyscall);
  ASSERT_THAT(result,
              StatusIs(absl::StatusCode::kInternal, HasSubstr("syscall")));
}

TEST(RunnerTest, BreakpointSnap) {
  ASSERT_OK_AND_ASSIGN(auto result, RunOneSnap(TestSnapshot::kBreakpoint));
  ASSERT_FALSE(result.success());
  EXPECT_EQ(result.player_result().outcome,
            PlaybackOutcome::kExecutionMisbehave);
  const snapshot_types::Endpoint& ep =
      result.player_result().actual_end_state->endpoint();
  Snapshot breakpointSnap =
      MakeSnapRunnerTestSnapshot<Host>(TestSnapshot::kBreakpoint);
  GRegSet<Host> gregs;
  ASSERT_TRUE(DeserializeGRegs(breakpointSnap.registers().gregs(), &gregs));
  const uint64_t start_address = gregs.GetInstructionPointer();
  EXPECT_EQ(ep.sig_instruction_address(), start_address);
  // The docs say that si_addr should be set for SIGTRAP, but empirically
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
  ASSERT_OK_AND_ASSIGN(auto result, RunOneSnap(TestSnapshot::kRunaway));
  ASSERT_FALSE(result.success());
  EXPECT_EQ(result.player_result().outcome, PlaybackOutcome::kExecutionRunaway);
}

TEST(RunnerTest, Deadline) {
  ASSERT_OK_AND_ASSIGN(auto result,
                       RunOneSnap(TestSnapshot::kRunaway, absl::Seconds(2)));
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
      RunnerLocation(), path, "", [&path] { unlink(path.c_str()); });
  auto opts = RunnerOptions::Default();
  ASSERT_OK(driver.Run(opts));
  opts.set_sequential_mode(true);
  ASSERT_OK(driver.Run(opts));
}

TEST(RunnerTest, UnknownFlags) {
  MmappedMemoryPtr<char> buffer =
      GenerateRelocatableSnaps(Host::architecture_id, {});
  ASSERT_OK_AND_ASSIGN(auto path, CreateTempFile("EmptyCorpus", ""));

  int fd = open(path.c_str(), O_WRONLY);
  ASSERT_NE(fd, -1);
  absl::string_view buf(buffer.get(), MmappedMemorySize(buffer));
  ASSERT_TRUE(WriteToFileDescriptor(fd, buf));
  close(fd);

  RunnerDriver driver = RunnerDriver::ReadingRunner(
      RunnerLocation(), path, "", [&path] { unlink(path.c_str()); });
  RunnerOptions opts = RunnerOptions::PlayOptions("<bogus>");
  opts.set_extra_argv({"--foobar=1"});
  absl::StatusOr<RunnerDriver::RunResult> result = driver.Run(opts);
  ASSERT_THAT(result, StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace silifuzz
