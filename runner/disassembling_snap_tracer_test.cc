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
#include "absl/status/statusor.h"
#include "./common/snapshot_enums.h"
#include "./runner/driver/runner_driver.h"
#include "./runner/runner_provider.h"
#include "./snap/testing/snap_test_snapshots.h"
#include "./snap/testing/snap_test_types.h"
#include "./util/testing/status_matchers.h"

namespace silifuzz {
namespace {

using silifuzz::testing::IsOk;
using silifuzz::testing::StatusIs;
using snapshot_types::SigNum;
using ::testing::ElementsAre;

RunnerDriver HelperDriver() {
  return RunnerDriver::BakedRunner(RunnerTestHelperLocation());
}

TEST(DisassemblingSnapTracer, TraceAsExpected) {
  RunnerDriver driver = HelperDriver();
  auto snapshot =
      MakeSnapRunnerTestSnapshot(SnapRunnerTestType::kEndsAsExpected);
  DisassemblingSnapTracer tracer(snapshot);
  auto result = driver.TraceOne(
      snapshot.id(), absl::bind_front(&DisassemblingSnapTracer::Step, &tracer));
  ASSERT_THAT(result, IsOk());
  ASSERT_TRUE(result->success());
  const auto& trace_result = tracer.trace_result();
  EXPECT_EQ(trace_result.instructions_executed, 2);
  EXPECT_THAT(trace_result.disassembly,
              ElementsAre("nop", "call qword ptr [rip]"));
}

TEST(DisassemblingSnapTracer, TraceSigill) {
  RunnerDriver driver = HelperDriver();
  auto snapshot = MakeSnapRunnerTestSnapshot(SnapRunnerTestType::kSigIll);
  DisassemblingSnapTracer tracer(snapshot);
  auto result = driver.TraceOne(
      snapshot.id(), absl::bind_front(&DisassemblingSnapTracer::Step, &tracer));
  ASSERT_THAT(result, IsOk());
  ASSERT_FALSE(result->success());
  ASSERT_TRUE(result->player_result().actual_end_state->endpoint().sig_num() ==
              SigNum::kSigIll);
}

TEST(DisassemblingSnapTracer, TraceNonDeterministic) {
  RunnerDriver driver = HelperDriver();
  auto snapshot =
      MakeSnapRunnerTestSnapshot(SnapRunnerTestType::kRegsMismatchRandom);
  DisassemblingSnapTracer tracer(snapshot);
  auto result = driver.TraceOne(
      snapshot.id(), absl::bind_front(&DisassemblingSnapTracer::Step, &tracer));
  ASSERT_THAT(result, StatusIs(absl::StatusCode::kInvalidArgument));
  const auto& trace_result = tracer.trace_result();
  EXPECT_EQ(trace_result.early_termination_reason,
            "Non-deterministic insn CPUID");
}

}  // namespace
}  // namespace silifuzz
