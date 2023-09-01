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

#include <optional>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/functional/bind_front.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./common/snapshot_enums.h"
#include "./common/snapshot_test_enum.h"
#include "./player/trace_options.h"
#include "./runner/driver/runner_driver.h"
#include "./runner/runner_provider.h"
#include "./snap/testing/snap_test_snapshots.h"
#include "./util/testing/status_macros.h"
#include "./util/testing/status_matchers.h"

namespace silifuzz {
namespace {

using silifuzz::testing::StatusIs;
using snapshot_types::SigNum;
using ::testing::ElementsAre;

RunnerDriver HelperDriver() {
  return RunnerDriver::BakedRunner(RunnerTestHelperLocation());
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
  ASSERT_OK_AND_ASSIGN(
      auto result,
      driver.TraceOne(
          snapshot.id(),
          absl::bind_front(&DisassemblingSnapTracer::Step, &tracer)));
  ASSERT_TRUE(result.success());
  const auto& trace_result = tracer.trace_result();
  EXPECT_EQ(trace_result.instructions_executed, 2);
  EXPECT_THAT(trace_result.disassembly,
              ElementsAre(InsnAtAddr("nop", 0x12355000, 1),
                          Insn("call qword ptr [rip]")));
}

TEST(DisassemblingSnapTracer, TraceSigill) {
  RunnerDriver driver = HelperDriver();
  auto snapshot = MakeSnapRunnerTestSnapshot<Host>(TestSnapshot::kSigIll);
  DisassemblingSnapTracer tracer(snapshot);
  ASSERT_OK_AND_ASSIGN(
      auto result,
      driver.TraceOne(
          snapshot.id(),
          absl::bind_front(&DisassemblingSnapTracer::Step, &tracer)));
  ASSERT_FALSE(result.success());
  ASSERT_TRUE(result.player_result().actual_end_state->endpoint().sig_num() ==
              SigNum::kSigIll);
}

TEST(DisassemblingSnapTracer, TraceNonDeterministic) {
  RunnerDriver driver = HelperDriver();
  auto snapshot =
      MakeSnapRunnerTestSnapshot<Host>(TestSnapshot::kRegsMismatchRandom);
  DisassemblingSnapTracer tracer(snapshot);
  auto result = driver.TraceOne(
      snapshot.id(), absl::bind_front(&DisassemblingSnapTracer::Step, &tracer));
  ASSERT_THAT(result, StatusIs(absl::StatusCode::kInvalidArgument));
  const auto& trace_result = tracer.trace_result();
  EXPECT_EQ(trace_result.early_termination_reason,
            "Non-deterministic insn CPUID");
}

TEST(DisassemblingSnapTracer, TraceSplitLock) {
  // Trace split-lock snapshot without split-lock trapping.
  RunnerDriver driver = HelperDriver();
  auto snapshot = MakeSnapRunnerTestSnapshot<Host>(TestSnapshot::kSplitLock);
  TraceOptions options = TraceOptions::Default();
  options.x86_filter_split_lock = false;
  DisassemblingSnapTracer tracer(snapshot, options);
  ASSERT_OK_AND_ASSIGN(
      const auto result,
      driver.TraceOne(
          snapshot.id(),
          absl::bind_front(&DisassemblingSnapTracer::Step, &tracer)));
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
  EXPECT_THAT(result2, StatusIs(absl::StatusCode::kInvalidArgument));
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
  ASSERT_OK_AND_ASSIGN(
      const auto result,
      driver.TraceOne(
          snapshot.id(),
          absl::bind_front(&DisassemblingSnapTracer::Step, &tracer)));
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
  EXPECT_THAT(result2, StatusIs(absl::StatusCode::kInvalidArgument));
  const auto& trace_result2 = vsyscall_region_access_tracer.trace_result();
  EXPECT_EQ(trace_result2.instructions_executed, 2);
  EXPECT_THAT(trace_result2.disassembly,
              ElementsAre(Insn("mov rax, 0xffffffffff600000"),
                          Insn("mov rbx, qword ptr [rax]")));
  EXPECT_EQ(trace_result2.early_termination_reason,
            "May access vsyscall region MOV");
}

}  // namespace
}  // namespace silifuzz
