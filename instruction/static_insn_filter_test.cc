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

#include "./instruction/static_insn_filter.h"

#include <stdint.h>

#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "./util/arch.h"

namespace silifuzz {

namespace {

std::string FromInts(std::vector<uint32_t>&& data) {
  return std::string(reinterpret_cast<char*>(&*data.begin()),
                     reinterpret_cast<char*>(&*data.end()));
}

#define EXPECT_AARCH64_FILTER_ACCEPT(insn) \
  EXPECT_TRUE(StaticInstructionFilter<AArch64>(FromInts(insn)))

#define EXPECT_AARCH64_FILTER_ACCEPT_CONFIG(insn, config) \
  EXPECT_TRUE(StaticInstructionFilter<AArch64>(FromInts(insn), config))

#define EXPECT_AARCH64_FILTER_REJECT(insn) \
  EXPECT_FALSE(StaticInstructionFilter<AArch64>(FromInts(insn)))

#define EXPECT_AARCH64_FILTER_REJECT_CONFIG(insn, config) \
  EXPECT_FALSE(StaticInstructionFilter<AArch64>(FromInts(insn), config))

TEST(StaticInsnFilter, SystemRegister) {
  // We'll want to filter our a number of system register accesses in the
  // future, but these should stay valid.
  // QEMU may accept malformed versions of these instructions that can be fixed
  // by a bitwise AND with ~0x00c00000

  // mrs    x0, tpidr_el0
  EXPECT_AARCH64_FILTER_ACCEPT({0xd53bd040});
  EXPECT_AARCH64_FILTER_REJECT({0xd5bbd040});

  // msr    fpcr, x23
  EXPECT_AARCH64_FILTER_ACCEPT({0xd51b4417});

  // mrs    x24, nzcv
  EXPECT_AARCH64_FILTER_ACCEPT({0xd53b4218});

  // Banned because some versions of QEMU fail to control access.
  // mrs    x28, cntp_tval_el0
  EXPECT_AARCH64_FILTER_REJECT({0xd53be21c});
  // mrs     x0, cntv_tval_el0
  EXPECT_AARCH64_FILTER_REJECT({0xd53be300});

  // Linux can emulate access to this register, and different kernel versions
  // can give different results.
  // mrs     x0, id_aa64mmfr0_el1
  EXPECT_AARCH64_FILTER_REJECT({0xd5380700});

  // Hardware random numbers are nondeterministic
  // mrs     x0, rndr
  EXPECT_AARCH64_FILTER_REJECT({0xd53b2400});
  // mrs     x0, rndrrs
  EXPECT_AARCH64_FILTER_REJECT({0xd53b2420});
}

TEST(StaticInsnFilter, LDXRB) {
  // The filter for store exclusive should not hit load exclusive.
  // ldxrb     w16, [x6]
  EXPECT_AARCH64_FILTER_ACCEPT({0x085f7cd0});
}

TEST(StaticInsnFilter, STR) {
  // The filter for store exclusive should not hit normal stores.
  // str     w16, [x6]
  EXPECT_AARCH64_FILTER_ACCEPT({0xb90000d0});
}

TEST(StaticInsnFilter, STXRB) {
  // Store exclusive is effectively non-deterministic.
  // stxrb     w4, w16, [x6]
  EXPECT_AARCH64_FILTER_REJECT({0x080400d0});
}

TEST(StaticInsnFilter, STXP) {
  // Store exclusive is effectively non-deterministic.
  // stxp     w11, w13, w21, [x6]
  EXPECT_AARCH64_FILTER_REJECT({0x882b54cd});
}

TEST(StaticInsnFilter, SVE) {
  InstructionFilterConfig<AArch64> banned =
      DEFAULT_INSTRUCTION_FILTER_CONFIG<AArch64>;
  banned.sve_instructions_allowed = false;
  InstructionFilterConfig<AArch64> allowed =
      DEFAULT_INSTRUCTION_FILTER_CONFIG<AArch64>;
  allowed.sve_instructions_allowed = true;

  // sqdecb    x11, vl8, mul #16
  EXPECT_AARCH64_FILTER_REJECT_CONFIG({0x043ff90b}, banned);
  EXPECT_AARCH64_FILTER_ACCEPT_CONFIG({0x043ff90b}, allowed);

  // ldff1sb   {z26.d}, p0/z, [x7, x4]
  EXPECT_AARCH64_FILTER_REJECT_CONFIG({0xa58460fa}, banned);
  EXPECT_AARCH64_FILTER_ACCEPT_CONFIG({0xa58460fa}, allowed);

  // ldff1h    {z11.s}, p3/z, [x17, z8.s, sxtw]
  EXPECT_AARCH64_FILTER_REJECT_CONFIG({0x84c86e2b}, banned);
  EXPECT_AARCH64_FILTER_ACCEPT_CONFIG({0x84c86e2b}, allowed);
}

TEST(StaticInsnFilter, Reserved) { EXPECT_AARCH64_FILTER_REJECT({0x00000000}); }

TEST(StaticInsnFilter, Unallocated) {
  EXPECT_AARCH64_FILTER_REJECT({0x675188e2});
  EXPECT_AARCH64_FILTER_REJECT({0x8383a5ea});
  EXPECT_AARCH64_FILTER_REJECT({0xc7285a07});
}

TEST(StaticInsnFilter, Hint) {
  // nop
  EXPECT_AARCH64_FILTER_ACCEPT({0xd503201f});

  // yield
  // Yield appears to be a hint for hardware multithreading, and we currently
  // don't have any chips with hardware multithreading to check if it does
  // anything pathalogical.  Assume it's OK since it doesn't trap.
  EXPECT_AARCH64_FILTER_ACCEPT({0xd503203f});

  // wfe
  // Can make the corpus run 2-3 orders of magnitude slower by waiting in EL0.
  EXPECT_AARCH64_FILTER_REJECT({0xd503205f});

  // wfi
  // Can make the corpus run 1-2 orders of magnitude slower by trapping to EL1.
  EXPECT_AARCH64_FILTER_REJECT({0xd503207f});

  // sev and sevl are questionable, since they can affect other processes.
  // We haven't found a situation where they actually cause a problem.  We're
  // leaving them in until we understand them better.

  // sev
  EXPECT_AARCH64_FILTER_ACCEPT({0xd503209f});

  // sevl
  EXPECT_AARCH64_FILTER_ACCEPT({0xd50320bf});
}

TEST(StaticInsnFilter, LoadStoreRegisterPAC) {
  // Standard load
  // ldr      x14, [x6, #1064]
  EXPECT_AARCH64_FILTER_ACCEPT({0xf94214ce});
  // PAC load
  // ldraa    x14, [x6, #1064]
  EXPECT_AARCH64_FILTER_REJECT({0xf82854ce});
  // A malformed encoding that should be rejected even if PAC enabled.
  EXPECT_AARCH64_FILTER_REJECT({0x782854ce});

  // Standard load
  // ldr      x29, [x7, #512]
  EXPECT_AARCH64_FILTER_ACCEPT({0xf94100fd});
  // PAC load
  // ldrab    x29, [x7, #512]
  EXPECT_AARCH64_FILTER_REJECT({0xf8a404fd});
}

TEST(StaticInsnFilter, BranchPAC) {
  // Standared indirect branch
  // br       x3
  EXPECT_AARCH64_FILTER_ACCEPT({0xd61f0060});
  // PAC indirect branch
  // braaz    x3
  EXPECT_AARCH64_FILTER_REJECT({0xd61f087f});
}

TEST(StaticInsnFilter, HintPAC) {
  // psb    csync
  EXPECT_AARCH64_FILTER_ACCEPT({0xd503223f});

  // hint    #0x76
  EXPECT_AARCH64_FILTER_ACCEPT({0xd5032edf});

  // pacibz
  EXPECT_AARCH64_FILTER_REJECT({0xd503235f});
}

TEST(StaticInsnFilter, DataPAC) {
  // clz        x30, x27
  EXPECT_AARCH64_FILTER_ACCEPT({0xdac0137e});

  // paciza    x17
  EXPECT_AARCH64_FILTER_REJECT({0xdac123f1});
}

TEST(StaticInsnFilter, LoadStore) {
  // Some sort of load / store, unsure what QEMU thinks it is.
  EXPECT_AARCH64_FILTER_REJECT({0xcd8070e5});

  // st1    {v31.4h, v0.4h, v1.4h}, [x6]
  EXPECT_AARCH64_FILTER_ACCEPT({0x0c0064df});
  EXPECT_AARCH64_FILTER_REJECT({0x0c1e64df});

  // st4    {v0.8h-v3.8h}, [x7]
  EXPECT_AARCH64_FILTER_ACCEPT({0x4c0004e0});
  EXPECT_AARCH64_FILTER_REJECT({0x4c0c04e0});

  // ld1    {v20.b}[8], [x6]
  EXPECT_AARCH64_FILTER_ACCEPT({0x4d4000d4});
  EXPECT_AARCH64_FILTER_REJECT({0x4d5e00d4});
}

TEST(StaticInsnFilter, CompareAndSwap) {
  // QEMU may accept malformed version of these instruction that can be fixed by
  // a bitwise OR with 0x00007c00

  // casl     x0, x24, [x6]
  EXPECT_AARCH64_FILTER_ACCEPT({0xc8a0fcd8});
  EXPECT_AARCH64_FILTER_REJECT({0xc8a0ecd8});
  EXPECT_AARCH64_FILTER_REJECT({0xc8a0f8d8});

  // casl     w4, w14, [x6]
  EXPECT_AARCH64_FILTER_ACCEPT({0x88a4fcce});
  EXPECT_AARCH64_FILTER_REJECT({0x88a4e4ce});
}

TEST(StaticInsnFilter, Atomics) {
  // ldumax   w5, w1, [x7]
  EXPECT_AARCH64_FILTER_ACCEPT({0xb82560e1});
  EXPECT_AARCH64_FILTER_REJECT({0xb825e0e1});
}

TEST(StaticInsnFilter, AddSubtractExtendedRegister) {
  // QEMU may accept malformed version of these instruction that can be fixed by
  // a bitwise AND with ~0x00c00000

  // adds     w0, w0, w2, uxtb
  EXPECT_AARCH64_FILTER_ACCEPT({0x2b220000});
  EXPECT_AARCH64_FILTER_REJECT({0x2be20000});

  // cmp      x3, w21, uxtb
  EXPECT_AARCH64_FILTER_ACCEPT({0xeb35007f});
  EXPECT_AARCH64_FILTER_REJECT({0xebb5007f});
}

TEST(StaticInsnFilter, DataProcessingOneSource) {
  // rev32     x19, x3
  EXPECT_AARCH64_FILTER_ACCEPT({0xdac00873});
  EXPECT_AARCH64_FILTER_REJECT({0xdac08873});

  // rbit      x3, x12
  EXPECT_AARCH64_FILTER_ACCEPT({0xdac00183});
  EXPECT_AARCH64_FILTER_REJECT({0xdac04183});
}

TEST(StaticInsnFilter, FloatingPointDataProcessing) {
  // QEMU may accept malformed version of these instruction that can be fixed by
  // a bitwise AND with ~0xa0000000

  // 2 input
  // fmin      s7, s16, s8
  EXPECT_AARCH64_FILTER_ACCEPT({0x1e285a07});
  EXPECT_AARCH64_FILTER_REJECT({0xbe285a07});

  // 3 input
  // fnmadd    s4, s20, s8, s22
  EXPECT_AARCH64_FILTER_ACCEPT({0x1f285a84});
  EXPECT_AARCH64_FILTER_REJECT({0x3f285a84});
}

TEST(StaticInsnFilter, FloatingPointImmediate) {
  // QEMU may accept malformed version of these instruction that can be fixed by
  // a bitwise AND with ~0xa00003e0

  // fmov     s16, #-1.640625000000000000e-01
  EXPECT_AARCH64_FILTER_ACCEPT({0x1e38b010});
  EXPECT_AARCH64_FILTER_REJECT({0x9e38b2d0});
}

}  // namespace

}  // namespace silifuzz
