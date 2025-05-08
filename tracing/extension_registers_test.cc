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

#include "./tracing/extension_registers.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "./util/arch.h"
#include "./util/reg_group_set.h"

namespace silifuzz {

namespace {

struct X86NoERegs {
  static constexpr bool avx = false;
  static constexpr bool avx512 = false;
};
struct X86AVX {
  static constexpr bool avx = true;
  static constexpr bool avx512 = false;
};
struct X86AVX512 {
  static constexpr bool avx = true;
  static constexpr bool avx512 = true;
};

struct AArch64NoERegs {
  static constexpr uint16_t vl = 0;
};
struct AArch64SVE16 {
  static constexpr uint16_t vl = 16;
};
struct AArch64SVE64 {
  static constexpr uint16_t vl = 64;
};
struct AArch64SVE256 {
  static constexpr uint16_t vl = 256;
};

// Typed test boilerplate
template <typename TestParam>
struct ExtUContextTest : ::testing::Test {};
using arch_eregs_typelist = ::testing::Types<
    std::pair<X86_64, X86NoERegs>, std::pair<X86_64, X86AVX>,
    std::pair<X86_64, X86AVX512>, std::pair<AArch64, AArch64NoERegs>,
    std::pair<AArch64, AArch64SVE16>, std::pair<AArch64, AArch64SVE64>,
    std::pair<AArch64, AArch64SVE256>>;
TYPED_TEST_SUITE(ExtUContextTest, arch_eregs_typelist);

// Setup the extension registers part in the RegGroupSet based on the given
// spec.
template <typename ERegsSpec>
void SetupERegs(ExtUContext<X86_64>& ucontext) {
  if constexpr (ERegsSpec::avx) {
    ucontext.eregs.register_groups.SetAVX(true);
  }
  if constexpr (ERegsSpec::avx512) {
    ucontext.eregs.register_groups.SetAVX512(true);
  }
}

template <typename ERegsSpec>
void SetupERegs(ExtUContext<AArch64>& ucontext) {
  ucontext.eregs.register_groups.SetSVEVectorWidth(ERegsSpec::vl);
}

// Fill the targeted registers with the given data and ERegsSpec.
template <typename ERegsSpec>
void SetTargetedRegs(uint8_t data, ExtUContext<X86_64>& ucontext) {
  memset(&ucontext.gregs.rbx, data, sizeof(ucontext.gregs.rbx));
  memset(&ucontext.fpregs.xmm[3], data, sizeof(ucontext.fpregs.xmm[3]));
  if constexpr (ERegsSpec::avx) {
    memset(&ucontext.eregs.ymm[3], data, sizeof(ucontext.eregs.ymm[3]));
  }
  if constexpr (ERegsSpec::avx512) {
    memset(&ucontext.eregs.zmm[3], data, sizeof(ucontext.eregs.zmm[3]));
  }
}

template <typename ERegsSpec>
void SetTargetedRegs(uint8_t data, ExtUContext<AArch64>& ucontext) {
  memset(&ucontext.gregs.x[3], data, sizeof(ucontext.gregs.x[3]));
  memset(&ucontext.fpregs.v[3], data, sizeof(ucontext.fpregs.v[3]));
  constexpr const size_t vl = ERegsSpec::vl;
  memset(&ucontext.eregs.z[vl * 3], data, vl);
}

MATCHER_P2(isFilledWith, size, value, "") {
  std::vector<uint8_t> data_vec(reinterpret_cast<const uint8_t*>(arg),
                                reinterpret_cast<const uint8_t*>(arg) + size);
  *result_listener << "data: " << testing::PrintToString(data_vec);
  return testing::Matches(testing::Each(testing::Eq(value)))(data_vec);
}

void CheckTargetedRegs(uint8_t expected, const ExtUContext<X86_64>& ucontext) {
  EXPECT_THAT(&ucontext.gregs.rbx,
              isFilledWith(sizeof(ucontext.gregs.rbx), expected));
  EXPECT_THAT(&ucontext.fpregs.xmm[3],
              isFilledWith(sizeof(ucontext.fpregs.xmm[3]), expected));
  if (ucontext.eregs.register_groups.GetAVX()) {
    EXPECT_THAT(&ucontext.eregs.ymm[3],
                isFilledWith(sizeof(ucontext.eregs.ymm[3]), expected));
  }
  if (ucontext.eregs.register_groups.GetAVX512()) {
    EXPECT_THAT(&ucontext.eregs.zmm[3],
                isFilledWith(sizeof(ucontext.eregs.zmm[3]), expected));
  }
}

void CheckTargetedRegs(uint8_t expected, const ExtUContext<AArch64>& ucontext) {
  EXPECT_THAT(&ucontext.gregs.x[3],
              isFilledWith(sizeof(ucontext.gregs.x[3]), expected));
  EXPECT_THAT(&ucontext.fpregs.v[3],
              isFilledWith(sizeof(ucontext.fpregs.v[3]), expected));
  const size_t vl = ucontext.eregs.register_groups.GetSVEVectorWidth();
  if (vl > 0) {
    EXPECT_THAT(&ucontext.eregs.z[vl * 3], isFilledWith(vl, expected));
  }
}

TYPED_TEST(ExtUContextTest, Equals) {
  using Arch = typename TypeParam::first_type;
  using ERegsSpec = typename TypeParam::second_type;
  ExtUContext<Arch> a;
  memset(&a, 0, sizeof(a));
  SetTargetedRegs<ERegsSpec>(12, a);

  // 1. simple equal
  ExtUContext<Arch> b = a;
  EXPECT_EQ(a, b);
  // 2. when data is same, ExtUContext equality <-> RegGroupSet equality
  SetupERegs<ERegsSpec>(b);
  EXPECT_EQ(a == b, a.eregs.register_groups == b.eregs.register_groups);
  // 3. simple not equal
  ExtUContext<Arch> empty;
  memset(&empty, 0, sizeof(empty));
  EXPECT_NE(a, empty);
  // 4. equal: eregs not enabled, eregs data is different, but ignored
  ExtUContext<Arch> c;
  memset(&c, 0, sizeof(c));
  c.gregs = a.gregs;
  c.fpregs = a.fpregs;
  a.eregs.register_groups = RegisterGroupSet<Arch>();
  EXPECT_EQ(a, c);
  // 5. when eregs data is different but rest is the same, two ExtUContexts are
  // equal iff eregs are not enabled.
  SetupERegs<ERegsSpec>(a);
  SetupERegs<ERegsSpec>(c);
  ASSERT_EQ(a.eregs.register_groups, c.eregs.register_groups);
  EXPECT_EQ(a == c, !a.HasERegs());
}

TEST(ExtUContextSimpleTest, HasERegs) {
  ExtUContext<X86_64> ucontext1;
  memset(&ucontext1, 0, sizeof(ucontext1));

  EXPECT_FALSE(ucontext1.HasERegs());
  ucontext1.eregs.register_groups.SetAVX(true);
  EXPECT_TRUE(ucontext1.HasERegs());
  ucontext1.eregs.register_groups.SetAVX512(true);
  EXPECT_TRUE(ucontext1.HasERegs());
  ucontext1.eregs.register_groups.SetAVX(false);
  EXPECT_TRUE(ucontext1.HasERegs());

  ExtUContext<AArch64> ucontext2;
  memset(&ucontext2, 0, sizeof(ucontext2));
  for (int vl = 16; vl <= 256; vl += 16) {
    ucontext2.eregs.register_groups.SetSVEVectorWidth(vl);
    EXPECT_TRUE(ucontext2.HasERegs());
  }
}

TYPED_TEST(ExtUContextTest, BitDiff) {
  using Arch = typename TypeParam::first_type;
  using ERegsSpec = typename TypeParam::second_type;

  ExtUContext<Arch> a, b, diff, empty;
  memset(&a, 0, sizeof(a));
  memset(&b, 0, sizeof(b));
  memset(&empty, 0, sizeof(empty));

  SetupERegs<ERegsSpec>(a);
  SetupERegs<ERegsSpec>(b);
  SetupERegs<ERegsSpec>(empty);

  SetTargetedRegs<ERegsSpec>(0x33, a);
  SetTargetedRegs<ERegsSpec>(0xff, b);
  BitDiff(a, b, diff);

  CheckTargetedRegs(0xff ^ 0x33, diff);
  // Check the rest of the registers are zero.
  SetTargetedRegs<ERegsSpec>(0, diff);
  EXPECT_EQ(diff, empty);
}

TYPED_TEST(ExtUContextTest, AccumulateToggle) {
  using Arch = typename TypeParam::first_type;
  using ERegsSpec = typename TypeParam::second_type;
  ExtUContext<Arch> a, b, zero_one, one_zero, empty;
  memset(&a, 0, sizeof(a));
  memset(&b, 0, sizeof(b));
  memset(&zero_one, 0, sizeof(zero_one));
  memset(&one_zero, 0, sizeof(one_zero));
  memset(&empty, 0, sizeof(empty));

  SetupERegs<ERegsSpec>(a);
  SetupERegs<ERegsSpec>(b);
  SetupERegs<ERegsSpec>(zero_one);
  SetupERegs<ERegsSpec>(one_zero);
  SetupERegs<ERegsSpec>(empty);

  SetTargetedRegs<ERegsSpec>(0x55, a);
  SetTargetedRegs<ERegsSpec>(0x33, b);
  AccumulateToggle(a, b, zero_one, one_zero);

  // 0x55 -> 0x33
  CheckTargetedRegs((~0x55 & 0x33), zero_one);
  CheckTargetedRegs((0x55 & ~0x33), one_zero);

  AccumulateToggle(b, a, zero_one, one_zero);
  CheckTargetedRegs((0x55 ^ 0x33), zero_one);
  CheckTargetedRegs((0x55 ^ 0x33), one_zero);

  // Check if the rest of the registers are zero.
  SetTargetedRegs<ERegsSpec>(0, zero_one);
  SetTargetedRegs<ERegsSpec>(0, one_zero);
  EXPECT_EQ(zero_one, empty);
  EXPECT_EQ(one_zero, empty);
}

TYPED_TEST(ExtUContextTest, PopCount) {
  using Arch = typename TypeParam::first_type;
  using ERegsSpec = typename TypeParam::second_type;
  ExtUContext<Arch> ucontext;
  memset(&ucontext, 0, sizeof(ucontext));

  EXPECT_EQ(PopCount(ucontext), 0);
  SetTargetedRegs<ERegsSpec>(0x33, ucontext);
  if constexpr (std::is_same_v<Arch, X86_64>) {
    EXPECT_EQ(PopCount(ucontext), 4 * (sizeof(ucontext.gregs.rbx) +
                                       sizeof(ucontext.fpregs.xmm[3])));
  } else if constexpr (std::is_same_v<Arch, AArch64>) {
    EXPECT_EQ(PopCount(ucontext),
              4 * (sizeof(ucontext.gregs.x[3]) + sizeof(ucontext.fpregs.v[3])));
  }

  memset(&ucontext, 0, sizeof(ucontext));
  SetupERegs<ERegsSpec>(ucontext);
  SetTargetedRegs<ERegsSpec>(0x33, ucontext);
  if constexpr (std::is_same_v<ERegsSpec, X86NoERegs>) {
    EXPECT_EQ(PopCount(ucontext), 4 * (sizeof(ucontext.gregs.rbx) +
                                       sizeof(ucontext.fpregs.xmm[3])));
  } else if constexpr (std::is_same_v<ERegsSpec, X86AVX>) {
    EXPECT_EQ(PopCount(ucontext),
              4 * (sizeof(ucontext.gregs.rbx) + sizeof(ucontext.eregs.ymm[3])));
  } else if constexpr (std::is_same_v<ERegsSpec, X86AVX512>) {
    EXPECT_EQ(PopCount(ucontext),
              4 * (sizeof(ucontext.gregs.rbx) + sizeof(ucontext.eregs.zmm[3])));
  } else if constexpr (std::is_same_v<ERegsSpec, AArch64NoERegs>) {
    EXPECT_EQ(PopCount(ucontext),
              4 * (sizeof(ucontext.gregs.x[3]) + sizeof(ucontext.fpregs.v[3])));
  } else if constexpr (std::is_same_v<ERegsSpec, AArch64SVE16>) {
    EXPECT_EQ(PopCount(ucontext), 4 * (sizeof(ucontext.gregs.x[3]) + 16));
  } else if constexpr (std::is_same_v<ERegsSpec, AArch64SVE64>) {
    EXPECT_EQ(PopCount(ucontext), 4 * (sizeof(ucontext.gregs.x[3]) + 64));
  } else if constexpr (std::is_same_v<ERegsSpec, AArch64SVE256>) {
    EXPECT_EQ(PopCount(ucontext), 4 * (sizeof(ucontext.gregs.x[3]) + 256));
  }
}

}  // namespace

}  // namespace silifuzz
