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

#include "./common/static_insn_filter.h"

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

#define EXPECT_AARCH64_FILTER_REJECT(insn) \
  EXPECT_FALSE(StaticInstructionFilter<AArch64>(FromInts(insn)))

TEST(StaticInsnFilter, ReadTPIDR) {
  // We'll want to filter our a number of system register accesses in the
  // future, but these should stay valid.
  // QEMU may accept malformed versions of these instructions that can be fixed
  // by a bitwise AND with ~0x00c00000

  // mrs    x0, tpidr_el0
  EXPECT_AARCH64_FILTER_ACCEPT({0xd53bd040});
  EXPECT_AARCH64_FILTER_REJECT({0xd5bbd040});
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

TEST(StaticInsnFilter, Reserved) { EXPECT_AARCH64_FILTER_REJECT({0x00000000}); }

TEST(StaticInsnFilter, Unallocated) {
  EXPECT_AARCH64_FILTER_REJECT({0x675188e2});
  EXPECT_AARCH64_FILTER_REJECT({0x8383a5ea});
  EXPECT_AARCH64_FILTER_REJECT({0xc7285a07});
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
  // yield
  EXPECT_AARCH64_FILTER_ACCEPT({0xd503203f});

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
  // ldff1h    {z11.s}, p3/z, [x17, z8.s, sxtw]
  EXPECT_AARCH64_FILTER_ACCEPT({0x84c86e2b});

  // Some sort of load / store, unsure what QEMU thinks it is.
  EXPECT_AARCH64_FILTER_REJECT({0xcd8070e5});
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
