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

#include <cstdint>
#include <cstdlib>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/macros.h"
#include "./common/snapshot_test_config.h"
#include "./util/testing/status_matchers.h"
#include "./util/ucontext/ucontext.h"

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

// Check the registers are what we expect after executing the SimpleTestSnippet.
template <typename Arch>
void CheckRegisters(const UContext<Arch>& ucontext);

template <>
void CheckRegisters(const UContext<X86_64>& ucontext) {
  EXPECT_EQ(ucontext.gregs.rdx, 2);
  EXPECT_EQ(ucontext.gregs.rcx, 3);
  EXPECT_EQ(ucontext.gregs.r8, 4);
}

template <>
void CheckRegisters(const UContext<AArch64>& ucontext) {
  EXPECT_EQ(ucontext.gregs.x[2], 2);
  EXPECT_EQ(ucontext.gregs.x[3], 3);
  EXPECT_EQ(ucontext.gregs.x[4], 4);
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
  UContext<TypeParam> ucontext;
  tracer.GetRegisters(ucontext);
  CheckRegisters(ucontext);
}

// Unicorn doesn't provide access to some registers, zero them out to make the
// test work.
template <typename Arch>
void ZeroOutUnimplementedRegs(UContext<Arch>& ucontext);

template <>
void ZeroOutUnimplementedRegs<X86_64>(UContext<X86_64>& ucontext) {
  ucontext.fpregs.fcw = 0;
  ucontext.fpregs.fsw = 0;
  ucontext.fpregs.ftw = 0;
  ucontext.fpregs.fop = 0;
  ucontext.fpregs.rip = 0;
  ucontext.fpregs.rdp = 0;
  ucontext.fpregs.mxcsr_mask = 0;
}

template <>
void ZeroOutUnimplementedRegs<AArch64>(UContext<AArch64>& ucontext) {
  ucontext.fpregs.fpcr = 0;
  ucontext.fpregs.fpsr = 0;
}

// Not ever reg can accept arbitrary bit patterns, fix up the randomized values
// so that they will be accepted.
template <typename Arch>
void FixupRandomRegs(UContext<Arch>& ucontext);

constexpr __uint128_t kEightyBitMask = static_cast<__uint128_t>(0xffff) | ~0ULL;

template <>
void FixupRandomRegs<X86_64>(UContext<X86_64>& ucontext) {
  // Unicorn will discard parts of eflags, set it to a constant rather than
  // trying to reverse engineer the exact bits that are preserved.
  ucontext.gregs.eflags = 0x202;

  // Unicorn will not accept all values for fs and gs, zero them for simplicity.
  ucontext.gregs.fs = 0;
  ucontext.gregs.gs = 0;

  // Only eighty bits of FP registers are touched.
  for (__uint128_t& st : ucontext.fpregs.st) {
    st &= kEightyBitMask;
  }
}

template <>
void FixupRandomRegs<AArch64>(UContext<AArch64>& ucontext) {
  // Only NZCV supported
  ucontext.gregs.pstate &= 0xf0000000;
}

template <typename Arch>
void RandomizeRegisters(UContext<Arch>& ucontext) {
  uint8_t* bytes = reinterpret_cast<uint8_t*>(&ucontext);
  for (size_t i = 0; i < sizeof(ucontext); i++) {
    bytes[i] = std::rand();
  }
  ZeroOutRegsPadding(&ucontext);
  FixupRandomRegs(ucontext);
}

TYPED_TEST(UnicornTracerTest, SetGetRegisters) {
  std::string instructions = SimpleTestSnippet<TypeParam>();

  UnicornTracer<TypeParam> tracer;
  ASSERT_THAT(tracer.InitSnippet(instructions), IsOk());

  UContext<TypeParam> src, dst;
  RandomizeRegisters(src);
  memset(&dst, 0, sizeof(dst));

  tracer.SetRegisters(src);
  tracer.GetRegisters(dst);

  // Done after SetRegisters so that we will notice if a field we think is
  // unimplemented actually works.
  ZeroOutUnimplementedRegs(src);

  EXPECT_EQ(src.gregs, dst.gregs);
  EXPECT_EQ(src.fpregs, dst.fpregs);
}

}  // namespace

}  // namespace silifuzz
