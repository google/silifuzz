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

#include <ios>
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

  // Not supported, yet.
  // mrs    x22, ssbs
  EXPECT_AARCH64_FILTER_REJECT({0xd53b42d6});

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

TEST(StaticInsnFilter, DataCache) {
  // dc    cvac, x0
  EXPECT_AARCH64_FILTER_ACCEPT({0xd50b7a20});
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
  InstructionFilterConfig<AArch64> banned = {
      .sve_instructions_allowed = false,
  };
  InstructionFilterConfig<AArch64> allowed = {
      .sve_instructions_allowed = true,
  };
  // sqdecb    x11, vl8, mul #16
  EXPECT_AARCH64_FILTER_REJECT_CONFIG({0x043ff90b}, banned);
  EXPECT_AARCH64_FILTER_ACCEPT_CONFIG({0x043ff90b}, allowed);
}

struct TestInstruction {
  std::string text;
  uint32_t insn;
  bool reject;
  bool sve;
};

std::vector<TestInstruction> GenerateTestInstructions() {
  // Because the encoding space for non-faulting memory operations is complex,
  // we're brute forcing the testing - checking a random version of each
  // possible ff/nf encoding as well as nearby encodings that should not be
  // banned.
  return std::vector<TestInstruction>{
      {
          .text = "ldff1b {z24.b}, p1/z, [x11, xzr]",
          .insn = 0xa41f6578,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1b {z29.b}, p3/z, [x2]",
          .insn = 0xa400ac5d,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1b {z20.b}, p3/z, [x23, x11]",
          .insn = 0xa40b6ef4,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1b {z13.b}, p7/z, [x28, x12]",
          .insn = 0xa40c5f8d,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1b {z12.h}, p0/z, [x28, xzr]",
          .insn = 0xa43f638c,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1b {z29.h}, p2/z, [x0]",
          .insn = 0xa420a81d,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1b {z20.h}, p1/z, [x13, x21]",
          .insn = 0xa43565b4,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1b {z4.h}, p3/z, [x8, x11]",
          .insn = 0xa42b4d04,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1b {z25.s}, p5/z, [x16, xzr]",
          .insn = 0xa45f7619,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1b {z1.s}, p3/z, [x1]",
          .insn = 0xa440ac21,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1b {z15.s}, p1/z, [x0, x29]",
          .insn = 0xa45d640f,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1b {z4.s}, p5/z, [x3, x3]",
          .insn = 0xa4435464,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1b {z7.d}, p3/z, [x22, xzr]",
          .insn = 0xa47f6ec7,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1b {z1.d}, p4/z, [x5]",
          .insn = 0xa460b0a1,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1b {z28.d}, p7/z, [x23, x28]",
          .insn = 0xa47c7efc,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1b {z13.d}, p4/z, [x0, x7]",
          .insn = 0xa467500d,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1sb {z6.h}, p6/z, [x7, xzr]",
          .insn = 0xa5df78e6,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1sb {z21.h}, p4/z, [x2]",
          .insn = 0xa5c0b055,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1sb {z30.h}, p3/z, [x30, x27]",
          .insn = 0xa5db6fde,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1sb {z28.h}, p6/z, [x22, x22]",
          .insn = 0xa5d65adc,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1sb {z8.s}, p7/z, [x24, xzr]",
          .insn = 0xa5bf7f08,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1sb {z2.s}, p7/z, [x23]",
          .insn = 0xa5a0bee2,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1sb {z11.s}, p5/z, [x10, x3]",
          .insn = 0xa5a3754b,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1sb {z18.s}, p0/z, [x17, x30]",
          .insn = 0xa5be4232,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1sb {z26.d}, p5/z, [x28, xzr]",
          .insn = 0xa59f779a,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1sb {z0.d}, p0/z, [x1]",
          .insn = 0xa580a020,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1sb {z30.d}, p2/z, [x11, x25]",
          .insn = 0xa599697e,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1sb {z27.d}, p6/z, [x19, x9]",
          .insn = 0xa5895a7b,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1b {z9.d}, p1/z, [x17, z28.d, uxtw]",
          .insn = 0xc41c6629,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1b {z26.d}, p5/z, [x24, z28.d, sxtw]",
          .insn = 0xc45c571a,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1b {z18.s}, p6/z, [x15, z29.s, sxtw]",
          .insn = 0x845d79f2,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1b {z27.s}, p7/z, [x1, z31.s, uxtw]",
          .insn = 0x841f5c3b,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1b {z28.d}, p2/z, [x24, z1.d]",
          .insn = 0xc441eb1c,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1b {z5.d}, p5/z, [x23, z15.d]",
          .insn = 0xc44fd6e5,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1sb {z28.d}, p6/z, [x15, z11.d, uxtw]",
          .insn = 0xc40b39fc,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1sb {z22.d}, p1/z, [x14, z2.d, sxtw]",
          .insn = 0xc44205d6,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1sb {z7.s}, p0/z, [x18, z20.s, uxtw]",
          .insn = 0x84142247,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1sb {z1.s}, p1/z, [x25, z13.s, sxtw]",
          .insn = 0x844d0721,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1sb {z17.d}, p2/z, [x7, z26.d]",
          .insn = 0xc45aa8f1,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1sb {z30.d}, p0/z, [x19, z13.d]",
          .insn = 0xc44d827e,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1b {z8.s}, p0/z, [z20.s]",
          .insn = 0x8420e288,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1b {z26.s}, p0/z, [z23.s]",
          .insn = 0x8420c2fa,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1b {z13.s}, p4/z, [z2.s, #8]",
          .insn = 0x8428f04d,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1b {z11.s}, p4/z, [z23.s, #8]",
          .insn = 0x8428d2eb,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1b {z23.d}, p6/z, [z16.d]",
          .insn = 0xc420fa17,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1b {z4.d}, p2/z, [z30.d]",
          .insn = 0xc420cbc4,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1b {z28.d}, p6/z, [z13.d, #24]",
          .insn = 0xc438f9bc,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1b {z5.d}, p6/z, [z28.d, #16]",
          .insn = 0xc430db85,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1sb {z13.s}, p1/z, [z12.s]",
          .insn = 0x8420a58d,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1sb {z27.s}, p2/z, [z28.s]",
          .insn = 0x84208b9b,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1sb {z8.s}, p0/z, [z19.s, #16]",
          .insn = 0x8430a268,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1sb {z28.s}, p1/z, [z27.s, #24]",
          .insn = 0x8438877c,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1sb {z18.d}, p0/z, [z25.d]",
          .insn = 0xc420a332,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1sb {z11.d}, p5/z, [z16.d]",
          .insn = 0xc420960b,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1sb {z26.d}, p4/z, [z17.d, #24]",
          .insn = 0xc438b23a,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1sb {z6.d}, p0/z, [z19.d, #16]",
          .insn = 0xc4308266,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1d {z29.d}, p1/z, [x16, xzr, lsl #3]",
          .insn = 0xa5ff661d,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1d {z6.d}, p1/z, [x8]",
          .insn = 0xa5e0a506,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1d {z11.d}, p3/z, [x11, x17, lsl #3]",
          .insn = 0xa5f16d6b,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1d {z12.d}, p3/z, [x23, x28, lsl #3]",
          .insn = 0xa5fc4eec,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1d {z8.d}, p5/z, [x18, z27.d, sxtw #3]",
          .insn = 0xc5fb7648,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1d {z11.d}, p7/z, [x11, z25.d, uxtw #3]",
          .insn = 0xc5b95d6b,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1d {z2.d}, p7/z, [x29, z22.d, uxtw]",
          .insn = 0xc5967fa2,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1d {z3.d}, p6/z, [x15, z24.d, sxtw]",
          .insn = 0xc5d859e3,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1d {z30.d}, p2/z, [x21, z9.d, lsl #3]",
          .insn = 0xc5e9eabe,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1d {z3.d}, p1/z, [x26, z30.d, lsl #3]",
          .insn = 0xc5fec743,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1d {z25.d}, p5/z, [x22, z25.d]",
          .insn = 0xc5d9f6d9,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1d {z18.d}, p1/z, [x2, z18.d]",
          .insn = 0xc5d2c452,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1d {z26.d}, p3/z, [z10.d]",
          .insn = 0xc5a0ed5a,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1d {z29.d}, p2/z, [z2.d]",
          .insn = 0xc5a0c85d,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1d {z25.d}, p4/z, [z4.d, #16]",
          .insn = 0xc5a2f099,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1d {z24.d}, p0/z, [z26.d, #16]",
          .insn = 0xc5a2c358,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1h {z6.h}, p0/z, [x9, xzr, lsl #1]",
          .insn = 0xa4bf6126,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1h {z12.h}, p3/z, [x4]",
          .insn = 0xa4a0ac8c,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1h {z29.h}, p0/z, [x9, x27, lsl #1]",
          .insn = 0xa4bb613d,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1h {z7.h}, p6/z, [x23, x12, lsl #1]",
          .insn = 0xa4ac5ae7,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1h {z11.s}, p4/z, [x5, xzr, lsl #1]",
          .insn = 0xa4df70ab,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1h {z9.s}, p5/z, [x27]",
          .insn = 0xa4c0b769,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1h {z20.s}, p3/z, [x13, x30, lsl #1]",
          .insn = 0xa4de6db4,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1h {z31.s}, p5/z, [x5, x30, lsl #1]",
          .insn = 0xa4de54bf,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1h {z3.d}, p4/z, [x25, xzr, lsl #1]",
          .insn = 0xa4ff7323,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1h {z24.d}, p1/z, [x6]",
          .insn = 0xa4e0a4d8,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1h {z31.d}, p6/z, [x20, x7, lsl #1]",
          .insn = 0xa4e77a9f,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1h {z3.d}, p7/z, [x23, x16, lsl #1]",
          .insn = 0xa4f05ee3,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1sh {z2.s}, p2/z, [x18, xzr, lsl #1]",
          .insn = 0xa53f6a42,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1sh {z20.s}, p0/z, [x22]",
          .insn = 0xa520a2d4,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1sh {z6.s}, p1/z, [x3, x28, lsl #1]",
          .insn = 0xa53c6466,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1sh {z30.s}, p4/z, [x3, x1, lsl #1]",
          .insn = 0xa521507e,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1sh {z10.d}, p2/z, [x1, xzr, lsl #1]",
          .insn = 0xa51f682a,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1sh {z16.d}, p1/z, [x15]",
          .insn = 0xa500a5f0,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1sh {z9.d}, p1/z, [x7, x30, lsl #1]",
          .insn = 0xa51e64e9,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1sh {z13.d}, p4/z, [x1, x20, lsl #1]",
          .insn = 0xa514502d,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1h {z15.s}, p7/z, [x29, z10.s, uxtw #1]",
          .insn = 0x84aa7faf,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1h {z17.s}, p7/z, [x28, z13.s, uxtw #1]",
          .insn = 0x84ad5f91,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1h {z3.d}, p3/z, [x2, z7.d, uxtw #1]",
          .insn = 0xc4a76c43,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1h {z31.d}, p2/z, [x3, z20.d, sxtw #1]",
          .insn = 0xc4f4487f,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1h {z31.d}, p5/z, [x11, z13.d, sxtw]",
          .insn = 0xc4cd757f,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1h {z11.d}, p1/z, [x21, z14.d, sxtw]",
          .insn = 0xc4ce46ab,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1h {z21.s}, p1/z, [x20, z30.s, uxtw]",
          .insn = 0x849e6695,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1h {z18.s}, p2/z, [x7, z11.s, uxtw]",
          .insn = 0x848b48f2,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1h {z18.d}, p7/z, [x2, z21.d, lsl #1]",
          .insn = 0xc4f5fc52,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1h {z23.d}, p6/z, [x6, z1.d, lsl #1]",
          .insn = 0xc4e1d8d7,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1h {z15.d}, p6/z, [x12, z13.d]",
          .insn = 0xc4cdf98f,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1h {z30.d}, p3/z, [x7, z22.d]",
          .insn = 0xc4d6ccfe,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1sh {z28.s}, p0/z, [x11, z12.s, uxtw #1]",
          .insn = 0x84ac217c,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1sh {z28.s}, p4/z, [x0, z3.s, uxtw #1]",
          .insn = 0x84a3101c,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1sh {z28.d}, p3/z, [x16, z12.d, sxtw #1]",
          .insn = 0xc4ec2e1c,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1sh {z1.d}, p6/z, [x10, z1.d, sxtw #1]",
          .insn = 0xc4e11941,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1sh {z27.d}, p5/z, [x17, z6.d, uxtw]",
          .insn = 0xc486363b,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1sh {z0.d}, p6/z, [x8, z0.d, sxtw]",
          .insn = 0xc4c01900,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1sh {z14.s}, p2/z, [x6, z0.s, uxtw]",
          .insn = 0x848028ce,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1sh {z8.s}, p1/z, [x15, z3.s, uxtw]",
          .insn = 0x848305e8,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1sh {z16.d}, p7/z, [x22, z30.d, lsl #1]",
          .insn = 0xc4febed0,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1sh {z10.d}, p5/z, [x1, z22.d, lsl #1]",
          .insn = 0xc4f6942a,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1h {z22.s}, p5/z, [z15.s]",
          .insn = 0x84a0f5f6,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1h {z23.s}, p7/z, [z16.s]",
          .insn = 0x84a0de17,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1h {z5.s}, p2/z, [z2.s, #24]",
          .insn = 0x84ace845,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1h {z4.s}, p5/z, [z24.s, #24]",
          .insn = 0x84acd704,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1h {z22.d}, p6/z, [z19.d]",
          .insn = 0xc4a0fa76,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1h {z18.d}, p7/z, [z28.d]",
          .insn = 0xc4a0df92,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1h {z13.d}, p0/z, [z14.d, #8]",
          .insn = 0xc4a4e1cd,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1h {z27.d}, p2/z, [z18.d, #8]",
          .insn = 0xc4a4ca5b,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1sh {z8.s}, p4/z, [z10.s]",
          .insn = 0x84a0b148,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1sh {z17.s}, p2/z, [z3.s]",
          .insn = 0x84a08871,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1sh {z11.s}, p0/z, [z2.s, #8]",
          .insn = 0x84a4a04b,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1sh {z7.s}, p5/z, [z22.s, #8]",
          .insn = 0x84a496c7,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1sh {z13.d}, p0/z, [z20.d]",
          .insn = 0xc4a0a28d,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1sh {z30.d}, p2/z, [z25.d]",
          .insn = 0xc4a08b3e,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1sh {z2.d}, p7/z, [z7.d, #24]",
          .insn = 0xc4acbce2,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1sh {z7.d}, p4/z, [z24.d, #16]",
          .insn = 0xc4a89307,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1w {z25.s}, p4/z, [x3, xzr, lsl #2]",
          .insn = 0xa55f7079,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1w {z2.s}, p2/z, [x24]",
          .insn = 0xa540ab02,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1w {z5.s}, p7/z, [x11, x5, lsl #2]",
          .insn = 0xa5457d65,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1w {z23.s}, p0/z, [x14, x6, lsl #2]",
          .insn = 0xa54641d7,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1w {z3.d}, p6/z, [x5, xzr, lsl #2]",
          .insn = 0xa57f78a3,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1w {z1.d}, p5/z, [x0]",
          .insn = 0xa560b401,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1w {z8.d}, p3/z, [x22, x11, lsl #2]",
          .insn = 0xa56b6ec8,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1w {z13.d}, p3/z, [x13, x10, lsl #2]",
          .insn = 0xa56a4dad,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1sw {z6.d}, p4/z, [x6, xzr, lsl #2]",
          .insn = 0xa49f70c6,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1sw {z1.d}, p7/z, [x1]",
          .insn = 0xa480bc21,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1sw {z29.d}, p4/z, [x15, x25, lsl #2]",
          .insn = 0xa49971fd,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1sw {z28.d}, p4/z, [x6, x25, lsl #2]",
          .insn = 0xa49950dc,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1w {z10.s}, p2/z, [x2, z6.s, uxtw #2]",
          .insn = 0x8526684a,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1w {z18.s}, p0/z, [x28, z23.s, sxtw #2]",
          .insn = 0x85774392,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1w {z3.d}, p3/z, [x14, z26.d, sxtw #2]",
          .insn = 0xc57a6dc3,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1w {z17.d}, p6/z, [x28, z26.d, sxtw #2]",
          .insn = 0xc57a5b91,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1w {z30.d}, p1/z, [x13, z12.d, uxtw]",
          .insn = 0xc50c65be,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1w {z2.d}, p0/z, [x29, z10.d, sxtw]",
          .insn = 0xc54a43a2,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1w {z16.s}, p0/z, [x17, z29.s, sxtw]",
          .insn = 0x855d6230,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1w {z29.s}, p1/z, [x15, z6.s, uxtw]",
          .insn = 0x850645fd,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1w {z25.d}, p0/z, [x23, z10.d, lsl #2]",
          .insn = 0xc56ae2f9,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1w {z10.d}, p3/z, [x14, z3.d, lsl #2]",
          .insn = 0xc563cdca,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1w {z8.d}, p7/z, [x11, z1.d]",
          .insn = 0xc541fd68,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1w {z11.d}, p7/z, [x27, z6.d]",
          .insn = 0xc546df6b,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1sw {z25.d}, p2/z, [x17, z21.d, uxtw #2]",
          .insn = 0xc5352a39,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1sw {z20.d}, p4/z, [x24, z14.d, uxtw #2]",
          .insn = 0xc52e1314,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1sw {z31.d}, p7/z, [x5, z0.d, uxtw]",
          .insn = 0xc5003cbf,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1sw {z6.d}, p2/z, [x13, z11.d, uxtw]",
          .insn = 0xc50b09a6,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1sw {z10.d}, p6/z, [x21, z10.d, lsl #2]",
          .insn = 0xc56abaaa,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1sw {z23.d}, p3/z, [x20, z31.d, lsl #2]",
          .insn = 0xc57f8e97,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1sw {z21.d}, p3/z, [x17, z4.d]",
          .insn = 0xc544ae35,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1sw {z13.d}, p6/z, [x13, z27.d]",
          .insn = 0xc55b99ad,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1w {z6.s}, p2/z, [z26.s]",
          .insn = 0x8520eb46,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1w {z20.s}, p3/z, [z30.s]",
          .insn = 0x8520cfd4,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1w {z29.s}, p1/z, [z0.s, #16]",
          .insn = 0x8524e41d,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1w {z26.s}, p6/z, [z31.s, #8]",
          .insn = 0x8522dbfa,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1w {z7.d}, p3/z, [z15.d]",
          .insn = 0xc520ede7,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1w {z13.d}, p2/z, [z8.d]",
          .insn = 0xc520c90d,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1w {z4.d}, p1/z, [z3.d, #24]",
          .insn = 0xc526e464,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1w {z22.d}, p1/z, [z27.d, #24]",
          .insn = 0xc526c776,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1sw {z31.d}, p3/z, [z6.d]",
          .insn = 0xc520acdf,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1sw {z1.d}, p4/z, [z25.d]",
          .insn = 0xc5209321,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldff1sw {z30.d}, p7/z, [z1.d, #24]",
          .insn = 0xc526bc3e,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ld1sw {z22.d}, p5/z, [z1.d, #8]",
          .insn = 0xc5229436,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldnf1b {z16.b}, p2/z, [x19]",
          .insn = 0xa410aa70,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ldnf1b {z5.b}, p5/z, [x13, #-5, mul vl]",
          .insn = 0xa41bb5a5,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ldnf1b {z31.h}, p0/z, [x7]",
          .insn = 0xa430a0ff,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ldnf1b {z31.h}, p0/z, [x23, #4, mul vl]",
          .insn = 0xa434a2ff,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ldnf1b {z1.s}, p0/z, [x12]",
          .insn = 0xa450a181,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ldnf1b {z3.s}, p7/z, [x22, #2, mul vl]",
          .insn = 0xa452bec3,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ldnf1b {z25.d}, p4/z, [x30]",
          .insn = 0xa470b3d9,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ldnf1b {z30.d}, p7/z, [x0, #1, mul vl]",
          .insn = 0xa471bc1e,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ldnf1sb {z11.h}, p4/z, [x16]",
          .insn = 0xa5d0b20b,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ldnf1sb {z4.h}, p1/z, [x18, #5, mul vl]",
          .insn = 0xa5d5a644,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ldnf1sb {z30.s}, p3/z, [x1]",
          .insn = 0xa5b0ac3e,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ldnf1sb {z1.s}, p0/z, [x25, #6, mul vl]",
          .insn = 0xa5b6a321,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ldnf1sb {z29.d}, p2/z, [x9]",
          .insn = 0xa590a93d,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ldnf1sb {z8.d}, p3/z, [x5, #5, mul vl]",
          .insn = 0xa595aca8,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ldnf1d {z15.d}, p0/z, [x11]",
          .insn = 0xa5f0a16f,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ldnf1d {z6.d}, p0/z, [x22, #-6, mul vl]",
          .insn = 0xa5faa2c6,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ldnf1h {z29.h}, p4/z, [x3]",
          .insn = 0xa4b0b07d,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ldnf1h {z19.h}, p2/z, [x29, #-3, mul vl]",
          .insn = 0xa4bdabb3,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ldnf1h {z19.s}, p6/z, [x9]",
          .insn = 0xa4d0b933,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ldnf1h {z14.s}, p3/z, [x18, #7, mul vl]",
          .insn = 0xa4d7ae4e,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ldnf1h {z8.d}, p5/z, [x16]",
          .insn = 0xa4f0b608,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ldnf1h {z10.d}, p4/z, [x4, #6, mul vl]",
          .insn = 0xa4f6b08a,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ldnf1sh {z3.s}, p2/z, [x19]",
          .insn = 0xa530aa63,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ldnf1sh {z30.s}, p5/z, [x11, #7, mul vl]",
          .insn = 0xa537b57e,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ldnf1sh {z28.d}, p0/z, [x25]",
          .insn = 0xa510a33c,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ldnf1sh {z17.d}, p3/z, [x21, #-4, mul vl]",
          .insn = 0xa51caeb1,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ldnf1w {z22.s}, p6/z, [x26]",
          .insn = 0xa550bb56,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ldnf1w {z25.s}, p1/z, [x16, #3, mul vl]",
          .insn = 0xa553a619,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ldnf1sw {z15.d}, p7/z, [x1]",
          .insn = 0xa490bc2f,
          .reject = true,
          .sve = true,
      },
      {
          .text = "ldnf1sw {z22.d}, p2/z, [x7, #5, mul vl]",
          .insn = 0xa495a8f6,
          .reject = true,
          .sve = true,
      },
      {
          .text = "prfb pldl1strm, p0, [x25]",
          .insn = 0x85c00321,
          .reject = false,
          .sve = true,
      },
      {
          .text = "prfb pstl3keep, p1, [x21, #8, mul vl]",
          .insn = 0x85c806ac,
          .reject = false,
          .sve = true,
      },
      {
          .text = "prfb pldl3strm, p5, [x0, x14]",
          .insn = 0x840ed405,
          .reject = false,
          .sve = true,
      },
      {
          .text = "prfb pstl1keep, p7, [x0, z31.s, uxtw]",
          .insn = 0x843f1c08,
          .reject = false,
          .sve = true,
      },
      {
          .text = "prfb pstl2keep, p5, [x29, z21.d, uxtw]",
          .insn = 0xc43517aa,
          .reject = false,
          .sve = true,
      },
      {
          .text = "prfb pstl1strm, p7, [x19, z25.d]",
          .insn = 0xc4799e69,
          .reject = false,
          .sve = true,
      },
      {
          .text = "prfb pstl3keep, p2, [z3.s]",
          .insn = 0x8400e86c,
          .reject = false,
          .sve = true,
      },
      {
          .text = "prfb pstl3strm, p0, [z26.s, #8]",
          .insn = 0x8408e34d,
          .reject = false,
          .sve = true,
      },
      {
          .text = "prfb pldl1strm, p0, [z9.d]",
          .insn = 0xc400e121,
          .reject = false,
          .sve = true,
      },
      {
          .text = "prfb pldl1keep, p3, [z11.d, #16]",
          .insn = 0xc410ed60,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldnt1w {z21.s}, p0/z, [x9]",
          .insn = 0xa500e135,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldnt1w {z5.s}, p0/z, [x26, #-4, mul vl]",
          .insn = 0xa50ce345,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldnt1w {z20.s}, p3/z, [x7, x0, lsl #2]",
          .insn = 0xa500ccf4,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldnt1w {z27.s}, p3/z, [z20.s, xzr]",
          .insn = 0x851fae9b,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldnt1w {z6.s}, p3/z, [z18.s, x17]",
          .insn = 0x8511ae46,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldnt1w {z15.d}, p4/z, [z30.d, xzr]",
          .insn = 0xc51fd3cf,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ldnt1w {z0.d}, p2/z, [z30.d, x28]",
          .insn = 0xc51ccbc0,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ld1rqh {z21.h}, p6/z, [x12]",
          .insn = 0xa4803995,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ld1rqh {z2.h}, p1/z, [x2, #32]",
          .insn = 0xa4822442,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ld1rqh {z4.h}, p1/z, [x24, x27, lsl #1]",
          .insn = 0xa49b0704,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ld1rd {z1.d}, p4/z, [x18]",
          .insn = 0x85c0f241,
          .reject = false,
          .sve = true,
      },
      {
          .text = "ld1rd {z22.d}, p1/z, [x11, #8]",
          .insn = 0x85c1e576,
          .reject = false,
          .sve = true,
      },
  };
}

TEST(StaticInsnFilter, NonFaultingMemoryOps) {
  // Memory operations that do not fault for a least one of the addresses they
  // load mean that the making process cannot determine all the memory addresses
  // a snapshot may access.

  std::vector<TestInstruction> test_instructions = GenerateTestInstructions();
  InstructionFilterConfig<AArch64> sve_banned = {
      .sve_instructions_allowed = false,
  };
  InstructionFilterConfig<AArch64> sve_allowed = {
      .sve_instructions_allowed = true,
  };

  for (const auto& test : test_instructions) {
    std::string bytes = FromInts({test.insn});
    EXPECT_EQ(StaticInstructionFilter<AArch64>(bytes, sve_allowed),
              !test.reject)
        << test.text;
    if (test.sve) {
      EXPECT_FALSE(StaticInstructionFilter<AArch64>(bytes, sve_banned))
          << test.text;
    }
  }
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

TEST(StaticInsnFilter, LoadStoreBanned) {
  InstructionFilterConfig<AArch64> banned = {
      .sve_instructions_allowed = true,
      .load_store_instructions_allowed = false,
  };
  InstructionFilterConfig<AArch64> with_sve{
      .sve_instructions_allowed = true,
  };
  std::vector<uint32_t> load_store_instructions = {
      0x0c0064df,  // st1 {v31.4h, v0.4h, v1.4h}, [x6]
      0xc8a0fcd8,  // stlxr w10, x24, [x6]
      0xb82560e1,  // ldumax   w5, w1, [x7]
      0x4d4000d4,  // ld1    {v20.b}[8], [x6]
      0xa5e0a000,  // ld1d   z0.d, p0/z, [x0]
      0xe0355545   // st1b    {za0h.b[w14, 5]}, p5, [x10, x21]
  };
  for (uint32_t instruction : load_store_instructions) {
    EXPECT_AARCH64_FILTER_ACCEPT_CONFIG({instruction}, with_sve)
        << std::hex << instruction
        << " must be accepted if loads are not banned";
    EXPECT_AARCH64_FILTER_REJECT_CONFIG({instruction}, banned)
        << std::hex << instruction;
  }

  // Test a few non-load-store insns.
  // fnmadd    s4, s20, s8, s22
  EXPECT_AARCH64_FILTER_ACCEPT_CONFIG({0x1f285a84}, banned);
  // br       x3
  EXPECT_AARCH64_FILTER_ACCEPT_CONFIG({0xd61f0060}, banned);
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
