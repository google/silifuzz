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

#include "./runner/disassembling_snap_tracer.h"

#include <sys/user.h>

#include <cstddef>
#include <optional>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/functional/bind_front.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./common/snapshot_enums.h"
#include "./common/snapshot_test_enum.h"
#include "./player/trace_options.h"
#include "./runner/driver/runner_driver.h"
#include "./runner/runner_provider.h"
#include "./snap/testing/snap_test_snapshots.h"
#include "./util/arch.h"
#include "./util/data_dependency.h"

namespace silifuzz {
namespace {

using snapshot_types::SigNum;
using ::testing::ElementsAre;
using ::testing::IsEmpty;
using ::testing::Not;

RunnerDriver HelperDriver() {
  return RunnerDriver::ReadingRunner(
      RunnerLocation(), GetDataDependencyFilepath("snap/testing/test_corpus"));
}

auto InsnAtAddr(absl::string_view x, int addr, int size) {
  return ::testing::HasSubstr(
      absl::StrCat("addr=0x", absl::Hex(addr), " size=", size, " ", x));
}

auto Insn(absl::string_view x) { return ::testing::HasSubstr(x); }

TEST(DisassemblingSnapTracer, TraceAsExpected) {
  RunnerDriver driver = HelperDriver();
  auto snapshot =
      MakeSnapRunnerTestSnapshot<Host>(TestSnapshot::kEndsAsExpected);
  DisassemblingSnapTracer tracer(snapshot);
  auto result = driver.TraceOne(
      snapshot.id(), absl::bind_front(&DisassemblingSnapTracer::Step, &tracer));
  ASSERT_TRUE(result.success());
  const auto& trace_result = tracer.trace_result();
  EXPECT_EQ(trace_result.instructions_executed, 2);
  EXPECT_THAT(trace_result.disassembly,
              ElementsAre(InsnAtAddr("nop", 0x32355000, 1),
                          Insn("call qword ptr [rip]")));
}

TEST(DisassemblingSnapTracer, TraceSigill) {
  RunnerDriver driver = HelperDriver();
  auto snapshot = MakeSnapRunnerTestSnapshot<Host>(TestSnapshot::kSigIll);
  DisassemblingSnapTracer tracer(snapshot);
  auto result = driver.TraceOne(
      snapshot.id(), absl::bind_front(&DisassemblingSnapTracer::Step, &tracer));
  ASSERT_FALSE(result.success());
  ASSERT_TRUE(
      result.failed_player_result().actual_end_state->endpoint().sig_num() ==
      SigNum::kSigIll);
}

TEST(DisassemblingSnapTracer, TraceNonDeterministic) {
  RunnerDriver driver = HelperDriver();
  auto snapshot =
      MakeSnapRunnerTestSnapshot<Host>(TestSnapshot::kRegsMismatchRandom);
  DisassemblingSnapTracer tracer(snapshot);
  auto result = driver.TraceOne(
      snapshot.id(), absl::bind_front(&DisassemblingSnapTracer::Step, &tracer));
  EXPECT_FALSE(result.success());
  const auto& trace_result = tracer.trace_result();
  EXPECT_EQ(trace_result.early_termination_reason, "Banned instruction: CPUID");
}

TEST(DisassemblingSnapTracer, TraceSplitLock) {
  // Trace split-lock snapshot without split-lock trapping.
  RunnerDriver driver = HelperDriver();
  auto snapshot = MakeSnapRunnerTestSnapshot<Host>(TestSnapshot::kSplitLock);
  TraceOptions options = TraceOptions::Default();
  options.x86_filter_split_lock = false;
  DisassemblingSnapTracer tracer(snapshot, options);
  const auto result = driver.TraceOne(
      snapshot.id(), absl::bind_front(&DisassemblingSnapTracer::Step, &tracer));
  EXPECT_FALSE(result.success());  // We don't have the correct endstate.
  const auto& trace_result = tracer.trace_result();
  EXPECT_EQ(trace_result.instructions_executed, 5);
  EXPECT_THAT(
      trace_result.disassembly,
      ElementsAre(Insn("mov rax, rsp"), Insn("dec rax"), Insn("xor al, al"),
                  Insn("lock inc dword ptr [rax-0x1]"),
                  Insn("call qword ptr [rip]")));

  // Trace again with split lock trapping enabled.
  options.x86_filter_split_lock = true;
  DisassemblingSnapTracer split_lock_tracer(snapshot, options);
  const auto result2 = driver.TraceOne(
      snapshot.id(),
      absl::bind_front(&DisassemblingSnapTracer::Step, &split_lock_tracer));
  EXPECT_FALSE(result2.success());
  const auto& trace_result2 = split_lock_tracer.trace_result();
  EXPECT_EQ(trace_result2.early_termination_reason, "Split-lock insn INC_LOCK");
}

TEST(DisassemblingSnapTracer, TraceVSyscallRegionAccess) {
  // Trace split-lock snapshot without split-lock trapping.
  RunnerDriver driver = HelperDriver();
  auto snapshot =
      MakeSnapRunnerTestSnapshot<Host>(TestSnapshot::kVSyscallRegionAccess);
  TraceOptions options = TraceOptions::Default();
  options.x86_filter_vsyscall_region_access = false;
  DisassemblingSnapTracer tracer(snapshot, options);
  const auto result = driver.TraceOne(
      snapshot.id(), absl::bind_front(&DisassemblingSnapTracer::Step, &tracer));
  EXPECT_FALSE(result.success());  // We don't have the correct endstate.
  const auto& trace_result = tracer.trace_result();
  // We may execute either 1 or 3 instruction depending on whether kernel
  // has legacy vsyscall configured.
  if (trace_result.instructions_executed == 3) {
    EXPECT_THAT(trace_result.disassembly,
                ElementsAre(Insn("mov rax, 0xffffffffff600000"),
                            Insn("mov rbx, qword ptr [rax]"),
                            Insn("call qword ptr [rip]")));

  } else {
    // vsyscall not configured for kernel. Snapshot should abort with a fault.
    EXPECT_EQ(trace_result.instructions_executed, 2);
    EXPECT_THAT(trace_result.disassembly,
                ElementsAre(Insn("mov rax, 0xffffffffff600000"),
                            Insn("mov rbx, qword ptr [rax]")));
    EXPECT_EQ(trace_result.early_termination_reason, "");
  }

  // Trace again with vsyscall region access filtering enabled.
  options.x86_filter_vsyscall_region_access = true;
  DisassemblingSnapTracer vsyscall_region_access_tracer(snapshot, options);
  const auto result2 = driver.TraceOne(
      snapshot.id(), absl::bind_front(&DisassemblingSnapTracer::Step,
                                      &vsyscall_region_access_tracer));
  EXPECT_FALSE(result2.success());
  const auto& trace_result2 = vsyscall_region_access_tracer.trace_result();
  EXPECT_EQ(trace_result2.instructions_executed, 2);
  EXPECT_THAT(trace_result2.disassembly,
              ElementsAre(Insn("mov rax, 0xffffffffff600000"),
                          Insn("mov rbx, qword ptr [rax]")));
  EXPECT_EQ(trace_result2.early_termination_reason,
            "May access vsyscall region MOV");
}

TEST(DisassemblingSnapTracer, TraceNonCanonicalEvexSp) {
  RunnerDriver driver = HelperDriver();
  auto snapshot =
      MakeSnapRunnerTestSnapshot<Host>(TestSnapshot::kNonCanonicalEvexSp);
  TraceOptions options = TraceOptions::Default();
  options.x86_filter_non_canonical_evex_sp = true;
  DisassemblingSnapTracer tracer(snapshot, options);
  const auto result = driver.TraceOne(
      snapshot.id(), absl::bind_front(&DisassemblingSnapTracer::Step, &tracer));
  EXPECT_FALSE(result.success());
  const auto& trace_result = tracer.trace_result();
  EXPECT_EQ(trace_result.early_termination_reason,
            "Non-canonical EVEX instruction");
}

TEST(DisassemblingSnapTracer, TraceMultipeTimes) {
  RunnerDriver driver = HelperDriver();
  auto snapshot =
      MakeSnapRunnerTestSnapshot<Host>(TestSnapshot::kEndsAsExpected);
  DisassemblingSnapTracer tracer(snapshot);
  constexpr size_t kNumIterations = 3;
  auto result = driver.TraceOne(
      snapshot.id(), absl::bind_front(&DisassemblingSnapTracer::Step, &tracer),
      kNumIterations);
  ASSERT_TRUE(result.success());
  const auto& trace_result = tracer.trace_result();
  EXPECT_EQ(trace_result.instructions_executed, 2 * kNumIterations);
  EXPECT_THAT(
      trace_result.disassembly,
      ElementsAre(
          InsnAtAddr("nop", 0x32355000, 1), Insn("call qword ptr [rip]"),
          InsnAtAddr("nop", 0x32355000, 1), Insn("call qword ptr [rip]"),
          InsnAtAddr("nop", 0x32355000, 1), Insn("call qword ptr [rip]")));
}

TEST(DisassemblingSnapTracer, TraceX86FilterMemoryAccess) {
  RunnerDriver driver = HelperDriver();
  auto snapshot =
      MakeSnapRunnerTestSnapshot<Host>(TestSnapshot::kMemoryMismatch);
  TraceOptions options = TraceOptions::Default();
  options.filter_memory_access = false;
  DisassemblingSnapTracer tracer(snapshot, options);
  const auto result = driver.TraceOne(
      snapshot.id(), absl::bind_front(&DisassemblingSnapTracer::Step, &tracer));
  // The test snapshot does not have a matching memory state.
  EXPECT_FALSE(result.success());
  const auto& trace_result = tracer.trace_result();
  // We should reach the snap exit.
  ASSERT_THAT(trace_result.disassembly, Not(IsEmpty()));
  EXPECT_THAT(trace_result.disassembly.back(), Insn("call qword ptr [rip]"));

  // Trace again with memory access filtering.
  // The exit instruction actually reads from memory but it is exempted.
  options.filter_memory_access = true;
  DisassemblingSnapTracer tracer_with_filter(snapshot, options);
  const auto result_with_filter = driver.TraceOne(
      snapshot.id(),
      absl::bind_front(&DisassemblingSnapTracer::Step, &tracer_with_filter));
  EXPECT_FALSE(result_with_filter.success());
  const auto& trace_result_with_filter = tracer_with_filter.trace_result();
  EXPECT_EQ(trace_result_with_filter.instructions_executed, 1);
  EXPECT_THAT(trace_result_with_filter.disassembly,
              ElementsAre(Insn("pushfq")));
  EXPECT_EQ(trace_result_with_filter.early_termination_reason,
            "Memory access not allowed");

  // Trace NOP snapshot with memory filtering. The indirect exit call should
  // be exempted.
  auto ends_as_expected_snapshot =
      MakeSnapRunnerTestSnapshot<Host>(TestSnapshot::kEndsAsExpected);
  DisassemblingSnapTracer ends_as_expected_tracer(ends_as_expected_snapshot,
                                                  options);
  const auto ends_as_expected_result =
      driver.TraceOne(ends_as_expected_snapshot.id(),
                      absl::bind_front(&DisassemblingSnapTracer::Step,
                                       &ends_as_expected_tracer));
  EXPECT_TRUE(ends_as_expected_result.success());
  const auto& ends_as_expected_trace_result =
      ends_as_expected_tracer.trace_result();
  EXPECT_EQ(ends_as_expected_trace_result.instructions_executed, 2);
  EXPECT_THAT(ends_as_expected_trace_result.disassembly,
              ElementsAre(Insn("nop"), Insn("call qword ptr [rip]")));
}

}  // namespace
}  // namespace silifuzz
