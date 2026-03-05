// Copyright 2024 The SiliFuzz Authors.
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
#include "absl/status/status.h"
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
#include "./util/testing/status_macros.h"
#include "./util/testing/status_matchers.h"

namespace silifuzz {
namespace {

using silifuzz::testing::StatusIs;
using snapshot_types::SigNum;
using ::testing::ElementsAre;
using ::testing::IsEmpty;
using ::testing::Not;

RunnerDriver HelperDriver() {
  return RunnerDriver::ReadingRunner(
      RunnerLocation(), GetDataDependencyFilepath("snap/testing/test_corpus"));
}

auto InsnAtAddr(absl::string_view x, int addr) {
  return ::testing::HasSubstr(absl::StrCat("addr=0x", absl::Hex(addr), " ", x));
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
  EXPECT_EQ(trace_result.instructions_executed, 4);
  EXPECT_THAT(trace_result.disassembly,
              ElementsAre(InsnAtAddr("nop ", 0x32355000),
                          Insn("stp x0, x30, [sp, #-0x10]"),
                          Insn("mov x0, #0xabcd0000"), Insn("blr x0")));
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
  EXPECT_EQ(trace_result.instructions_executed, 4 * kNumIterations);
  EXPECT_THAT(
      trace_result.disassembly,
      ElementsAre(
          InsnAtAddr("nop ", 0x32355000), Insn("stp x0, x30, [sp, #-0x10]"),
          Insn("mov x0, #0xabcd0000"), Insn("blr x0"),
          InsnAtAddr("nop ", 0x32355000), Insn("stp x0, x30, [sp, #-0x10]"),
          Insn("mov x0, #0xabcd0000"), Insn("blr x0"),
          InsnAtAddr("nop ", 0x32355000), Insn("stp x0, x30, [sp, #-0x10]"),
          Insn("mov x0, #0xabcd0000"), Insn("blr x0")));
}

TEST(DisassemblingSnapTracer, RejectIndirectBranches) {
  RunnerDriver driver = HelperDriver();
  auto snapshot =
      MakeSnapRunnerTestSnapshot<Host>(TestSnapshot::kIndirectBranch);
  TraceOptions trace_options = TraceOptions::Default();
  trace_options.aarch64_filter_indirect_branches = false;
  DisassemblingSnapTracer tracer(snapshot);
  auto result = driver.TraceOne(
      snapshot.id(), absl::bind_front(&DisassemblingSnapTracer::Step, &tracer));
  // We do not have the correct end state. So this is expected to fail.
  // However, the traces should be valid.
  EXPECT_FALSE(result.success());
  const auto& trace_result = tracer.trace_result();
  // The tracer should stop before executing the indirect branch 'br x0'.
  EXPECT_EQ(trace_result.instructions_executed, 7);
  EXPECT_THAT(trace_result.disassembly,
              ElementsAre(InsnAtAddr("bl #0x324b5004", 0x324b5000),
                          InsnAtAddr("add x0, x30, #8", 0x324b5004),
                          Insn("br x0"), InsnAtAddr("nop ", 0x324b500c),
                          Insn("stp x0, x30, [sp, #-0x10]"),
                          Insn("mov x0, #0xabcd0000"), Insn("blr x0")));

  TraceOptions trace_options_with_filter = TraceOptions::Default();
  trace_options_with_filter.aarch64_filter_indirect_branches = true;
  DisassemblingSnapTracer tracer_with_filter(snapshot,
                                             trace_options_with_filter);
  auto result_with_filter = driver.TraceOne(
      snapshot.id(),
      absl::bind_front(&DisassemblingSnapTracer::Step, &tracer_with_filter));
  ASSERT_FALSE(result_with_filter.success());
  const auto& trace_result_with_filter = tracer_with_filter.trace_result();
  EXPECT_THAT(trace_result_with_filter.early_termination_reason,
              ::testing::HasSubstr("Has problematic instructions."));
}

}  // namespace
}  // namespace silifuzz
