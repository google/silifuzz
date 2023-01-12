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

#include <endian.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "gtest/gtest.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

namespace {

static int run_bytes(std::vector<uint8_t>&& data) {
  return LLVMFuzzerTestOneInput(data.data(), data.size());
}

static int run_instructions(std::vector<uint32_t>&& data) {
  // Instructions should be little endian.
  for (size_t i = 0; i < data.size(); ++i) {
    data[i] = htole32(data[i]);
  }
  return LLVMFuzzerTestOneInput(reinterpret_cast<const uint8_t *>(data.data()),
                                data.size() * sizeof(uint32_t));
}

// The preprocessor does not understand initializer lists, so hack around this
// with vardic macros.
#define EXPECT_BYTES_ACCEPTED(...) EXPECT_EQ(0, run_bytes(__VA_ARGS__));
#define EXPECT_BYTES_REJECTED(...) EXPECT_EQ(-1, run_bytes(__VA_ARGS__));
#define EXPECT_INSTRUCTIONS_ACCEPTED(...) \
  EXPECT_EQ(0, run_instructions(__VA_ARGS__));
#define EXPECT_INSTRUCTIONS_REJECTED(...) \
  EXPECT_EQ(-1, run_instructions(__VA_ARGS__));

TEST(UnicornAarch64, Empty) {
  // Zero-length input should be rejected.
  EXPECT_INSTRUCTIONS_REJECTED({});
}

TEST(UnicornAarch64, CompleteInstruction) {
  // Only accept an input if the size is a multiple of 4.
  // 72b0c000        movk    w0, #0x8600, lsl #16
  EXPECT_BYTES_REJECTED({0x00, 0xc0, 0xb0});
  EXPECT_BYTES_ACCEPTED({0x00, 0xc0, 0xb0, 0x72});
  EXPECT_BYTES_REJECTED({0x00, 0xc0, 0xb0, 0x72, 0x00});
}

TEST(UnicornAarch64, MultipleInstructions) {
  // b0b0b0c0        adrp    x0, 0xffffffff62619000
  // f2194e39        ands    x25, x17, #0x7ffff8007ffff80
  // ca5a2735        eor     x21, x25, x26, lsr #9
  EXPECT_INSTRUCTIONS_ACCEPTED({0xb0b0b0c0, 0xf2194e39, 0xca5a2735});
}

TEST(UnicornAarch64, UDF) {
  // UDF should fault.
  EXPECT_INSTRUCTIONS_REJECTED({0x00000000});
}

TEST(UnicornAarch64, InfiniteLoop) {
  // Jump to the same instruction.
  // 14000000  b <beginning of this instruction>
  EXPECT_INSTRUCTIONS_REJECTED({0x14000000});

  // Two instruction loop.
  // 14000001  b <next>
  // 17ffffff  b <begin>
  EXPECT_INSTRUCTIONS_REJECTED({0x14000001, 0x17ffffff});
}

TEST(UnicornAarch64, TrivialBranch) {
  // Jump to the next instruction.
  // 14000001  b <end of this instruction>
  EXPECT_INSTRUCTIONS_ACCEPTED({0x14000001});

  // This will be an infinite loop if we don't skip the second instruction.
  // 14000002  b <end>
  // 17ffffff  b <begin>
  EXPECT_INSTRUCTIONS_ACCEPTED({0x14000002, 0x17ffffff});
}

TEST(UnicornAarch64, OutOfBounds) {
  // Jump one instruction after the next one.
  // 14000002  b <1 after>
  EXPECT_INSTRUCTIONS_REJECTED({0x14000002});

  // Jump one instruction before this one.
  // 17ffffff  b <1 before>
  EXPECT_INSTRUCTIONS_REJECTED({0x17ffffff});
}

TEST(UnicornAarch64, Stack) {
  // Make sure the stack is useable.
  // a9bf07e0  stp x0, x1, [sp, #-16]!
  // a8c107e0  ldp x0, x1, [sp], #16
  EXPECT_INSTRUCTIONS_ACCEPTED({0xa9bf07e0, 0xa8c107e0});

  // SP should initially point to an unmapped address.
  // a8c107e0  ldp x0, x1, [sp], #16
  EXPECT_INSTRUCTIONS_REJECTED({0xa8c107e0});
}

TEST(UnicornAarch64, Mem1) {
  // Make sure x6 points to usable memory.
  // f90000c0  str x0, [x6]
  // f94000c0  ldr x0, [x6]
  EXPECT_INSTRUCTIONS_ACCEPTED({0xf90000c0, 0xf94000c0});
}

TEST(UnicornAarch64, Mem2) {
  // Make sure x7 points to usable memory.
  // f90000e0  str x0, [x7]
  // f94000e0  ldr x0, [x7]
  EXPECT_INSTRUCTIONS_ACCEPTED({0xf90000c0, 0xf94000c0});
}

TEST(UnicornAarch64, EL0) {
  // As a baseline, these should still work.
  // d53bd040  mrs x0, tpidr_el0
  // d51bd040  msr tpidr_el0, x0
  EXPECT_INSTRUCTIONS_ACCEPTED({0xd53bd040, 0xd51bd040});

  // These instructions are privleged and should not work at EL0

  // d5087878  at s1e0w, x24
  EXPECT_INSTRUCTIONS_REJECTED({0xd5087878});

  // d518104d  msr cpacr_el1, x13
  EXPECT_INSTRUCTIONS_REJECTED({0xd518104d});
}

TEST(UnicornAarch64, ExceptionLevel) {
  // Any attempt to change the exception level should cause the instructions to
  // be rejected. This implicitly filters out syscalls, without regard to which
  // syscall it is.

  // Supervisor call (syscall)
  // d4000001  svc #0x0
  EXPECT_INSTRUCTIONS_REJECTED({0xd4000001});
  // Note that the exception location is after the instruction.

  // Hypervisor call
  // d4000002  hvc #0x0
  EXPECT_INSTRUCTIONS_REJECTED({0xd4000002});

  // Secure monitor call
  // d4000003  smc #0x0
  EXPECT_INSTRUCTIONS_REJECTED({0xd4000003});
}

TEST(UnicornAarch64, FloatingPoint) {
  // Floating point can be disabled in EL0 is CPACR_EL1 is misconfigured.
  // 6e6edf5a  fmul v26.2d, v26.2d, v14.2d
  EXPECT_INSTRUCTIONS_ACCEPTED({0x6e6edf5a});
}

}  // namespace
