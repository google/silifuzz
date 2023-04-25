// Copyright 2023 The SiliFuzz Authors.
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

#include "./tracing/unicorn_tracer.h"

#include <stdint.h>

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "./common/snapshot_test_config.h"
#include "./util/testing/status_matchers.h"

namespace silifuzz {

namespace {

using silifuzz::testing::IsOk;
using ::testing::Not;

template <typename Arch>
std::string SimpleTestSnippet() {
  return GetTestSnapshotConfig(
             static_cast<Snapshot::Architecture>(Arch::architecture_id),
             TestSnapshot::kSetThreeRegisters)
      ->instruction_bytes;
}

// Typed test boilerplate
using arch_typelist = ::testing::Types<ALL_ARCH_TYPES>;
template <class>
struct UnicornTracerTest : ::testing::Test {};
TYPED_TEST_SUITE(UnicornTracerTest, arch_typelist);

TYPED_TEST(UnicornTracerTest, NoInstructions) {
  std::string instructions;
  UnicornTracer<TypeParam> tracer;
  ASSERT_THAT(tracer.InitSnippet(instructions), IsOk());
  ASSERT_THAT(tracer.Run(0), IsOk());
}

TYPED_TEST(UnicornTracerTest, StoppedEarly) {
  std::string instructions = SimpleTestSnippet<TypeParam>();
  UnicornTracer<TypeParam> tracer;
  ASSERT_THAT(tracer.InitSnippet(instructions), IsOk());
  ASSERT_THAT(tracer.Run(2), Not(IsOk()));
}

TYPED_TEST(UnicornTracerTest, InstructionCallback) {
  std::string instructions = SimpleTestSnippet<TypeParam>();

  UnicornTracer<TypeParam> tracer;
  ASSERT_THAT(tracer.InitSnippet(instructions), IsOk());

  uint64_t instruction_count = 0;
  uint64_t instruction_bytes = 0;
  tracer.SetInstructionCallback(
      [&](UnicornTracer<TypeParam>* tracer, uint64_t address, uint32_t size) {
        instruction_count++;
        instruction_bytes += size;
      });

  ASSERT_THAT(tracer.Run(3), IsOk());
  EXPECT_EQ(instruction_count, 3);
  EXPECT_EQ(instruction_bytes, instructions.size());
}

}  // namespace

}  // namespace silifuzz
