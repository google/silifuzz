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
#include <sched.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdint>
#include <optional>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "./common/proxy_config.h"
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
#include "./util/cpu_id.h"
#include "./util/data_dependency.h"
#include "./util/file_util.h"
#include "./util/itoa.h"
#include "./util/mmapped_memory_ptr.h"
#include "./util/path_util.h"
#include "./util/subprocess.h"
#include "./util/testing/status_macros.h"
#include "./util/testing/status_matchers.h"
#include "./util/ucontext/serialize.h"
#include "./util/ucontext/ucontext_types.h"

namespace silifuzz {
namespace {

using snapshot_types::PlaybackOutcome;
using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::Not;

// Runs the given `snap` and returns the execution result.
//
// NOTE: Assumes that the snap is already built into the test helper binary.
RunnerDriver::RunResult RunOneSnap(
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
  auto result = RunOneSnap(TestSnapshot::kEndsAsExpected);
  ASSERT_TRUE(result.success());
}

TEST(RunnerTest, RegisterMismatchSnap) {
  auto result = RunOneSnap(TestSnapshot::kRegsMismatch);
  ASSERT_FALSE(result.success());
  EXPECT_EQ(result.failed_player_result().outcome,
            PlaybackOutcome::kRegisterStateMismatch);
}

TEST(RunnerTest, MemoryMismatchSnap) {
  auto result = RunOneSnap(TestSnapshot::kMemoryMismatch);
  ASSERT_FALSE(result.success());
  EXPECT_EQ(result.failed_player_result().outcome,
            PlaybackOutcome::kMemoryMismatch);
  const auto& end_state = *result.failed_player_result().actual_end_state;
  EXPECT_THAT(end_state.memory_bytes(), Not(IsEmpty()));

  Snapshot memoryMismatchSnap =
      MakeSnapRunnerTestSnapshot<Host>(TestSnapshot::kMemoryMismatch);
  EXPECT_EQ(end_state.endpoint().instruction_address(),
            memoryMismatchSnap.expected_end_states()[0]
                .endpoint()
                .instruction_address());
}

TEST(RunnerTest, SigSegvSnap) {
  auto result = RunOneSnap(TestSnapshot::kSigSegvReadFixable);
  ASSERT_FALSE(result.success());
  EXPECT_EQ(result.failed_player_result().outcome,
            PlaybackOutcome::kExecutionMisbehave);
  const Snapshot::EndState& end_state =
      *result.failed_player_result().actual_end_state;
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
  // kSigSevReadFixable test reads from start of data1 of proxy config.
  EXPECT_EQ(ep.sig_address(),
            DEFAULT_FUZZING_CONFIG<Host>.data1_range.start_address);
  EXPECT_EQ(ep.sig_num(), snapshot_types::SigNum::kSigSegv);
  EXPECT_EQ(ep.sig_cause(), snapshot_types::SigCause::kSegvCantRead);
}

TEST(RunnerTest, SyscallSnap) {
  auto result = RunOneSnap(TestSnapshot::kSyscall);
  ASSERT_FALSE(result.success());
  ASSERT_THAT(result.execution_result().message, HasSubstr("syscall"));
}

TEST(RunnerTest, BreakpointSnap) {
  auto result = RunOneSnap(TestSnapshot::kBreakpoint);
  ASSERT_FALSE(result.success());
  EXPECT_EQ(result.failed_player_result().outcome,
            PlaybackOutcome::kExecutionMisbehave);
  const snapshot_types::Endpoint& ep =
      result.failed_player_result().actual_end_state->endpoint();
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
  auto result = RunOneSnap(TestSnapshot::kRunaway);
  ASSERT_FALSE(result.success());
  EXPECT_EQ(result.failed_player_result().outcome,
            PlaybackOutcome::kExecutionRunaway);
}

TEST(RunnerTest, Deadline) {
  auto result = RunOneSnap(TestSnapshot::kRunaway, absl::Seconds(2));
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
  ASSERT_TRUE(driver.Run(opts).success());
  opts.set_sequential_mode(true);
  ASSERT_TRUE(driver.Run(opts).success());
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
  RunnerDriver::RunResult result = driver.Run(opts);
  ASSERT_FALSE(result.success());
  ASSERT_EQ(result.execution_result().code,
            RunnerDriver::ExecutionResult::Code::kInternalError);
}

// Verifies that --cpu pins playback to the requested core and reports that
// core's cpu_id on failure.
TEST(RunnerTest, CpuAffinity) {
  // Pick the last available CPU to exercise a non-zero core ID when possible.
  int pinned_cpu = kAnyCPUId;
  ForEachAvailableCPU([&pinned_cpu](int cpu) { pinned_cpu = cpu; });
  ASSERT_NE(pinned_cpu, kAnyCPUId);

  RunnerDriver driver = RunnerDriver::ReadingRunner(
      RunnerLocation(), GetDataDependencyFilepath("snap/testing/test_corpus"));
  RunnerDriver::RunResult ok_result =
      driver.PlayOne(EnumStr(TestSnapshot::kEndsAsExpected), pinned_cpu);
  EXPECT_TRUE(ok_result.success());

  RunnerDriver::RunResult mismatch_result =
      driver.PlayOne(EnumStr(TestSnapshot::kRegsMismatch), pinned_cpu);
  ASSERT_FALSE(mismatch_result.success());
  ASSERT_TRUE(mismatch_result.has_failed_player_result());
  EXPECT_EQ(mismatch_result.failed_player_result().outcome,
            PlaybackOutcome::kRegisterStateMismatch);
  EXPECT_EQ(mismatch_result.failed_player_result().cpu_id, pinned_cpu);
}

// Verifies that Main() sets CPU affinity before LoadCorpus() opens the corpus.
TEST(RunnerTest, CpuAffinitySetBeforeLoadingCorpus) {
  CpuSet saved_cpus;
  CPU_ZERO_S(kCpuSetBytes, saved_cpus.data());
  ASSERT_EQ(sched_getaffinity(0, kCpuSetBytes, saved_cpus.data()), 0);

  // Use a CPU ID < kMaxCpus (to pass SetCPUAffinity's bounds CHECK) and probe
  // sched_setaffinity directly to confirm it fails on this host.
  constexpr int kUnavailableCpu = kMaxCpus - 1;
  CpuSet probe_cpus;
  CPU_ZERO_S(kCpuSetBytes, probe_cpus.data());
  CPU_SET_S(kUnavailableCpu, kCpuSetBytes, probe_cpus.data());
  if (sched_setaffinity(0, kCpuSetBytes, probe_cpus.data()) == 0) {
    ASSERT_EQ(sched_setaffinity(0, kCpuSetBytes, saved_cpus.data()), 0);
    GTEST_SKIP() << "CPU " << kUnavailableCpu << " is available on this host.";
  }

  // With both an invalid --cpu and a nonexistent corpus file, the runner must
  // fail in SetCPUAffinity() before LoadCorpus() attempts to open the file.
  Subprocess::Options options = Subprocess::Options::Default();
  options.MapStderr(Subprocess::kMapToStdout).SetParentDeathSignal(SIGKILL);
  Subprocess runner_proc(options);
  ASSERT_OK(runner_proc.Start({RunnerLocation(),
                               absl::StrCat("--cpu=", kUnavailableCpu),
                               "/proc/self/nonexistent_corpus"}));
  std::string output;
  ProcessInfo info = runner_proc.Communicate(&output);
  ASSERT_TRUE(WIFEXITED(info.status));
  EXPECT_NE(WEXITSTATUS(info.status), 0);
  EXPECT_THAT(output, HasSubstr("Cannot pin cpu to core"));
  EXPECT_THAT(output, Not(HasSubstr("Failed to open corpus file")));
}

}  // namespace
}  // namespace silifuzz
