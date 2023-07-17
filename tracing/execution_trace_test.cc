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

#include "./tracing/execution_trace.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "./tracing/capstone_disassembler.h"
#include "./tracing/tracing_test_util.h"
#include "./tracing/unicorn_tracer.h"
#include "./util/arch.h"
#include "./util/testing/status_matchers.h"

namespace silifuzz {

namespace {

using silifuzz::testing::IsOk;

template <typename Arch>
void CheckInstructionInfo(CapstoneDisassembler<Arch>& disas, size_t i,
                          const UContext<Arch>& prev,
                          InstructionInfo<Arch>& info);

template <>
void CheckInstructionInfo(CapstoneDisassembler<X86_64>& disas, size_t i,
                          const UContext<X86_64>& prev,
                          InstructionInfo<X86_64>& info) {
  EXPECT_EQ(disas.InstructionIDName(info.instruction_id), "add");

  // rdx transitions 0 => 2 on the first instruction.
  EXPECT_EQ(prev.gregs.rdx, i <= 0 ? 0 : 2);
  EXPECT_EQ(info.ucontext.gregs.rdx, 2);

  // rcx transitions 0 => 3 on the second instruction.
  EXPECT_EQ(prev.gregs.rcx, i <= 1 ? 0 : 3);
  EXPECT_EQ(info.ucontext.gregs.rcx, i < 1 ? 0 : 3);

  // rdx transitions 0 => 4 on the third instruction.
  EXPECT_EQ(prev.gregs.r8, 0);
  EXPECT_EQ(info.ucontext.gregs.r8, i < 2 ? 0 : 4);
}

template <>
void CheckInstructionInfo(CapstoneDisassembler<AArch64>& disas, size_t i,
                          const UContext<AArch64>& prev,
                          InstructionInfo<AArch64>& info) {
  EXPECT_EQ(disas.InstructionIDName(info.instruction_id), "add");

  // x2 transitions 0 => 2 on the first instruction.
  EXPECT_EQ(prev.gregs.x[2], i <= 0 ? 0 : 2);
  EXPECT_EQ(info.ucontext.gregs.x[2], 2);

  // x3 transitions 0 => 3 on the second instruction.
  EXPECT_EQ(prev.gregs.x[3], i <= 1 ? 0 : 3);
  EXPECT_EQ(info.ucontext.gregs.x[3], i < 1 ? 0 : 3);

  // x4 transitions 0 => 4 on the third instruction.
  EXPECT_EQ(prev.gregs.x[4], 0);
  EXPECT_EQ(info.ucontext.gregs.x[4], i < 2 ? 0 : 4);
}

// Typed test boilerplate
using arch_typelist = ::testing::Types<ALL_ARCH_TYPES>;
template <class>
struct ExecutionTraceTest : ::testing::Test {};
TYPED_TEST_SUITE(ExecutionTraceTest, arch_typelist);

TYPED_TEST(ExecutionTraceTest, Simple) {
  std::string instructions = SimpleTestSnippet<TypeParam>();

  // There are three instructions and they should all be the same size, so the
  // size of the instruction sequence should be cleanly divisible by three.
  ASSERT_EQ(instructions.size() % 3, 0);
  const size_t instruction_size = instructions.size() / 3;

  UnicornTracer<TypeParam> tracer;
  ASSERT_THAT(tracer.InitSnippet(instructions), IsOk());

  CapstoneDisassembler<TypeParam> disas;

  ExecutionTrace<TypeParam> execution_trace(3);
  ASSERT_EQ(execution_trace.MaxInstructions(), 3);
  ASSERT_EQ(execution_trace.NumInstructions(), 0);

  // Capture the trace.
  ASSERT_THAT(CaptureTrace(tracer, disas, execution_trace), IsOk());
  ASSERT_EQ(execution_trace.NumInstructions(), 3);

  // Check the trace.
  size_t count = 0;
  execution_trace.ForEach([&](size_t i, UContext<TypeParam>& prev,
                              InstructionInfo<TypeParam>& info) {
    // Check it's in bounds.
    ASSERT_LT(i, 3);

    // Check it's sequential.
    EXPECT_EQ(i, count);
    count++;

    EXPECT_EQ(info.address,
              execution_trace.EntryAddress() + i * instruction_size);

    EXPECT_EQ(info.size, instruction_size);
    EXPECT_EQ(memcmp(info.bytes, &instructions[0] + i * instruction_size,
                     instruction_size),
              0);

    // Check the registers.
    CheckInstructionInfo(disas, i, prev, info);
  });
  EXPECT_EQ(count, 3);

  // Make sure Reset works.
  execution_trace.Reset();
  EXPECT_EQ(execution_trace.MaxInstructions(), 3);
  EXPECT_EQ(execution_trace.NumInstructions(), 0);
}

}  // namespace

}  // namespace silifuzz
