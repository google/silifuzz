// Copyright 2025 The SiliFuzz Authors.
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

#include "./tracing/native_tracer.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "./common/snapshot_test_config.h"
#include "./common/snapshot_test_enum.h"
#include "./tracing/tracer.h"
#include "./util/arch.h"
#include "./util/testing/status_matchers.h"

namespace silifuzz {

namespace {

using silifuzz::testing::IsOk;
using ::testing::Not;

TEST(NativeTracerTest, NoInstructions) {
  std::string instructions;
  NativeTracer tracer;
  ASSERT_THAT(tracer.InitSnippet(instructions), IsOk());
  int before_execution_count = 0;
  int before_instruction_count = 0;
  int after_execution_count = 0;
  tracer.SetBeforeExecutionCallback(
      [&](TracerControl<Host>& tracer) { before_execution_count++; });
  tracer.SetBeforeInstructionCallback(
      [&](TracerControl<Host>& tracer) { before_instruction_count++; });
  tracer.SetAfterExecutionCallback(
      [&](TracerControl<Host>& tracer) { after_execution_count++; });
  ASSERT_THAT(tracer.Run(0), IsOk());
  EXPECT_EQ(before_execution_count, 1);
  EXPECT_EQ(before_instruction_count, 0);
  EXPECT_EQ(after_execution_count, 1);
}

TEST(NativeTracerTest, Callbacks) {
  std::string instructions =
      GetTestSnippet<Host>(TestSnapshot::kSetThreeRegisters);
  NativeTracer tracer;
  ASSERT_THAT(tracer.InitSnippet(instructions), IsOk());
  int before_execution_count = 0;
  int before_instruction_count = 0;
  int after_execution_count = 0;
  tracer.SetBeforeExecutionCallback(
      [&](TracerControl<Host>& tracer) { before_execution_count++; });
  tracer.SetBeforeInstructionCallback(
      [&](TracerControl<Host>& tracer) { before_instruction_count++; });
  tracer.SetAfterExecutionCallback(
      [&](TracerControl<Host>& tracer) { after_execution_count++; });
  ASSERT_THAT(tracer.Run(3), IsOk());
  EXPECT_EQ(before_execution_count, 1);
  EXPECT_EQ(before_instruction_count, 3);
  EXPECT_EQ(after_execution_count, 1);
}

TEST(NativeTracerTest, InstructionLimit) {
  std::string instructions =
      GetTestSnippet<Host>(TestSnapshot::kSetThreeRegisters);
  NativeTracer tracer;
  ASSERT_THAT(tracer.InitSnippet(instructions), IsOk());
  ASSERT_THAT(tracer.Run(2), Not(IsOk()));
}

TEST(NativeTracerTest, UserStop) {
  std::string instructions =
      GetTestSnippet<Host>(TestSnapshot::kSetThreeRegisters);
  NativeTracer tracer;
  int count = 0;
  tracer.SetBeforeInstructionCallback([&](TracerControl<Host>& tracer) {
    if (++count == 2) tracer.Stop();
  });
  ASSERT_THAT(tracer.InitSnippet(instructions), IsOk());
  ASSERT_THAT(tracer.Run(1000), IsOk());
  ASSERT_EQ(count, 2);
}

}  // namespace

}  // namespace silifuzz
