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

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/strings/string_view.h"
#include "./common/snapshot_test_config.h"
#include "./common/snapshot_test_enum.h"
#include "./snap/exit_sequence.h"
#include "./tracing/tracer.h"
#include "./util/arch.h"
#include "./util/checks.h"
#include "./util/testing/status_matchers.h"
#include "./util/ucontext/ucontext.h"
#include "./util/ucontext/ucontext_types.h"

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
  EXPECT_EQ(count, 2);
}

// Not ever reg can accept arbitrary bit patterns, fix up the randomized values
// so that they will be accepted.
void FixupRandomRegs(const UContext<X86_64>& base, UContext<X86_64>& ucontext) {
  // Ptrace cannot set segment registers.
  ucontext.gregs.fs_base = base.gregs.fs_base;
  ucontext.gregs.gs_base = base.gregs.gs_base;
  ucontext.gregs.ss = base.gregs.ss;
  ucontext.gregs.cs = base.gregs.cs;
  ucontext.gregs.ds = base.gregs.ds;
  ucontext.gregs.es = base.gregs.es;
  ucontext.gregs.fs = base.gregs.fs;
  ucontext.gregs.gs = base.gregs.gs;

  // Some bits of eflags are ditched by ptrace. We set it to a constant rather
  // than trying to reverse engineer the exact bits that are preserved.
  ucontext.gregs.eflags = 0x302;
}

void FixupRandomRegs(const UContext<AArch64>& base,
                     UContext<AArch64>& ucontext) {
  // Only NZCV supported
  ucontext.gregs.pstate = ucontext.gregs.pstate & kPStateMask;
}

void ZeroOutUnimplementedRegs(UContext<X86_64>& ucontext) {}

void ZeroOutUnimplementedRegs(UContext<AArch64>& ucontext) {
  ucontext.gregs.tpidr = 0;
  ucontext.gregs.tpidrro = 0;
}

template <typename Arch>
void RandomizeRegisters(UContext<Arch>& ucontext) {
  std::srand(std::time(nullptr));
  uint8_t* bytes = reinterpret_cast<uint8_t*>(&ucontext);
  for (size_t i = 0; i < sizeof(ucontext); i++) {
    bytes[i] = std::rand();
  }
  ZeroOutRegsPadding(&ucontext);
}

TEST(NativeTracerTest, SetGetRegisters) {
  std::string instructions =
      GetTestSnippet<Host>(TestSnapshot::kSetThreeRegisters);

  NativeTracer tracer;
  ASSERT_THAT(tracer.InitSnippet(instructions), IsOk());

  UContext<Host> expected, actual;
  RandomizeRegisters(expected);
  memset(&actual, 0, sizeof(actual));

  tracer.SetBeforeExecutionCallback([&](TracerControl<Host>& tracer) {
    UContext<Host> base;
    tracer.GetRegisters(base);

    FixupRandomRegs(base, expected);

    tracer.SetRegisters(expected);
    tracer.GetRegisters(actual);
  });
  tracer.Run(0).IgnoreError();

  ZeroOutUnimplementedRegs(expected);
  EXPECT_EQ(expected.gregs, actual.gregs);
}

// Check the registers are what we expect after executing the
// "SetThreeRegisters" test snippet. `skip` indicates an instruction that has
// been skipped by the test, otherwise -1 if no instruction has been skipped.
// The snippet was designed to add three different constants (2, 3, 4) to three
// different registers that should have an initial value of zero.
template <typename Arch>
void CheckGRegs(const GRegSet<Arch>& gregs, int skip = -1);

template <>
void CheckGRegs(const GRegSet<X86_64>& gregs, int skip) {
  EXPECT_EQ(gregs.rdx, skip == 0 ? 0 : 2);
  EXPECT_EQ(gregs.rcx, skip == 1 ? 0 : 3);
  EXPECT_EQ(gregs.r8, skip == 2 ? 0 : 4);
}

template <>
void CheckGRegs(const GRegSet<AArch64>& gregs, int skip) {
  EXPECT_EQ(gregs.x[2], skip == 0 ? 0 : 2);
  EXPECT_EQ(gregs.x[3], skip == 1 ? 0 : 3);
  EXPECT_EQ(gregs.x[4], skip == 2 ? 0 : 4);
}

TEST(NativeTracerTest, SkipInstruction) {
  std::string instructions =
      GetTestSnippet<Host>(TestSnapshot::kSetThreeRegisters);

  for (int skip = 0; skip < 3; ++skip) {
    LOG_INFO("skipping instruction #", skip);
    NativeTracer tracer;
    ASSERT_THAT(tracer.InitSnippet(instructions), IsOk());

    int instruction = 0;
    const uint32_t size = 4;
    UContext<Host> init_ucontext;
    tracer.SetBeforeExecutionCallback([&](TracerControl<Host>& tracer) {
      tracer.GetRegisters(init_ucontext);
    });
    tracer.SetBeforeInstructionCallback([&](TracerControl<Host>& tracer) {
      uint64_t address = tracer.GetInstructionPointer();
      if (instruction == skip) {
        address += size;
        tracer.SetInstructionPointer(address);
      }
      if (tracer.IsInsideCode(address)) instruction++;
    });
    // Get final register state.
    UContext<Host> final_ucontext;
    tracer.SetAfterExecutionCallback([&](TracerControl<Host>& tracer) {
      tracer.GetRegisters(final_ucontext);
    });

    ASSERT_THAT(tracer.Run(3), IsOk());
    // Check that advancing the PC does not cause the next instruction callback
    // to be lost.
    CHECK_EQ(instruction, 2);
    CheckGRegs(final_ucontext.gregs, skip);
  }
}

constexpr size_t kReadMemoryBufferSize = 4096;

template <typename Arch>
constexpr uint8_t GetCodePadding();

template <>
constexpr uint8_t GetCodePadding<X86_64>() {
  return 0xcc;
}

template <>
constexpr uint8_t GetCodePadding<AArch64>() {
  return 0x0;
}

// Check the memory buffer contains the same data as in the code page of the
// snapshot. The expected data starts with the test_snippet followed by the
// exit_sequence. The remaining bytes are filled with padding bytes (0xcc for
// x86_64 and 0x0 for aarch64).
template <typename Arch>
void CheckMemory(const uint8_t* buffer, absl::string_view test_snippet) {
  uint8_t expected[kReadMemoryBufferSize];
  memset(expected, GetCodePadding<Arch>(), sizeof(expected));
  memcpy(expected, test_snippet.data(), test_snippet.size());
  WriteSnapExitSequence<Arch>(expected + test_snippet.size());
  EXPECT_EQ(memcmp(buffer, expected, kReadMemoryBufferSize), 0);
}

TEST(NativeTracerTest, ReadMemory) {
  std::string instructions =
      GetTestSnippet<Host>(TestSnapshot::kSetThreeRegisters);
  NativeTracer tracer;
  ASSERT_THAT(tracer.InitSnippet(instructions), IsOk());
  uint8_t buffer[kReadMemoryBufferSize];
  tracer.SetBeforeExecutionCallback([&](TracerControl<Host>& tracer) {
    tracer.ReadMemory(tracer.GetInstructionPointer(), &buffer, sizeof(buffer));
  });
  // The instruction limit of zero means the tracer will return an error.
  tracer.Run(0).IgnoreError();
  CheckMemory<Host>(buffer, instructions);
}
}  // namespace

}  // namespace silifuzz
