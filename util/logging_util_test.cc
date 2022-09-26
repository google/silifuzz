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

#include "./util/logging_util.h"

#include "gtest/gtest.h"
#include "./util/ucontext/ucontext.h"

namespace silifuzz {
namespace {

using arch_typelist = testing::Types<X86_64, AArch64>;
template <class>
struct LoggingUtilTest : testing::Test {};
TYPED_TEST_SUITE(LoggingUtilTest, arch_typelist);

void pattern_init(void* data, size_t size) {
  uint16_t* ptr = reinterpret_cast<uint16_t*>(data);
  for (int i = 0; i < size / sizeof(*ptr); ++i) {
    ptr[i] = (uint16_t)(i + 1) * 63073;
  }
}

GRegSet<X86_64> MakeDiff(const GRegSet<X86_64>& regs) {
  GRegSet<X86_64> base = regs;
  base.r10 = 0;
  return base;
}

GRegSet<AArch64> MakeDiff(const GRegSet<AArch64>& regs) {
  GRegSet<AArch64> base = regs;
  base.x[10] = 0;
  return base;
}

FPRegSet<X86_64> MakeDiff(const FPRegSet<X86_64>& regs) {
  FPRegSet<X86_64> base = regs;
  base.xmm[2] = 0;
  return base;
}

FPRegSet<AArch64> MakeDiff(const FPRegSet<AArch64>& regs) {
  FPRegSet<AArch64> base = regs;
  base.v[2] = 0;
  return base;
}

SignalRegSet MakeDiff(const SignalRegSet& regs) {
  SignalRegSet base = regs;
#if defined(__x86_64__)
  base.err = 0;
#elif defined(__aarch64__)
  base.esr = 0;
#else
#error "Unsupported architecture"
#endif
  return base;
}

// The following tests are fairly weak. They make sure the logging functions
// don't crash, and also allow the output to be visually inspected.

TYPED_TEST(LoggingUtilTest, GRegsDefault) {
  // Set up a randomized context.
  GRegSet<TypeParam> regs;
  pattern_init(&regs, sizeof(regs));
  ZeroOutGRegsPadding(&regs);
  LogGRegs(regs);
}

TYPED_TEST(LoggingUtilTest, GRegsWithBase) {
  // Set up a randomized context.
  GRegSet<TypeParam> regs;
  pattern_init(&regs, sizeof(regs));
  ZeroOutGRegsPadding(&regs);
  GRegSet<TypeParam> base = MakeDiff(regs);
  LogGRegs(regs, &base, false);
}

TYPED_TEST(LoggingUtilTest, GRegsWithDiff) {
  // Set up a randomized context.
  GRegSet<TypeParam> regs;
  pattern_init(&regs, sizeof(regs));
  ZeroOutGRegsPadding(&regs);
  GRegSet<TypeParam> base = MakeDiff(regs);
  LogGRegs(regs, &base, true);
}

TYPED_TEST(LoggingUtilTest, FPRegsDefault) {
  // Set up a randomized context.
  FPRegSet<TypeParam> regs;
  pattern_init(&regs, sizeof(regs));
  ZeroOutFPRegsPadding(&regs);
  LogFPRegs(regs);
}

TYPED_TEST(LoggingUtilTest, FPRegsWithBase) {
  // Set up a randomized context.
  FPRegSet<TypeParam> regs;
  pattern_init(&regs, sizeof(regs));
  ZeroOutFPRegsPadding(&regs);
  FPRegSet<TypeParam> base = MakeDiff(regs);
  LogFPRegs(regs, true, &base, false);
}

TYPED_TEST(LoggingUtilTest, FPRegsWithDiff) {
  // Set up a randomized context.
  FPRegSet<TypeParam> regs;
  pattern_init(&regs, sizeof(regs));
  ZeroOutFPRegsPadding(&regs);
  FPRegSet<TypeParam> base = MakeDiff(regs);
  LogFPRegs(regs, true, &base, true);
}

TEST(LoggingUtilSignalTest, SignalRegsDefault) {
  // Set up a randomized context.
  SignalRegSet regs;
  pattern_init(&regs, sizeof(regs));
  LogSignalRegs(regs);
}

TEST(LoggingUtilSignalTest, SignalRegsWithBase) {
  // Set up a randomized context.
  SignalRegSet regs;
  pattern_init(&regs, sizeof(regs));
  SignalRegSet base = MakeDiff(regs);
  LogSignalRegs(regs, &base, false);
}

TEST(LoggingUtilSignalTest, SignalRegsWithDiff) {
  // Set up a randomized context.
  SignalRegSet regs;
  pattern_init(&regs, sizeof(regs));
  SignalRegSet base = MakeDiff(regs);
  LogSignalRegs(regs, &base, true);
}

}  // namespace
}  // namespace silifuzz
