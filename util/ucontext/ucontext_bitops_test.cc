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

#include "./util/ucontext/ucontext_bitops.h"

#include "gtest/gtest.h"

namespace silifuzz {
namespace {

using arch_typelist = testing::Types<ALL_ARCH_TYPES>;

template <class>
struct UContextBitops : testing::Test {};
TYPED_TEST_SUITE(UContextBitops, arch_typelist);

TYPED_TEST(UContextBitops, PopCount) {
  UContext<TypeParam> uctx;
  UContextClear(uctx);
  EXPECT_EQ(0, UContextPopCount(uctx));

  memset(&uctx, 0xa5, 1);
  EXPECT_EQ(4, UContextPopCount(uctx));

  // Note: in the future, UContextPopCount may skip padding fields, so this
  // invariant is not guarenteed.
  memset(&uctx, 0xc4, sizeof(uctx));
  EXPECT_EQ(sizeof(uctx) * 3, UContextPopCount(uctx));
}

TYPED_TEST(UContextBitops, Diff) {
  UContext<TypeParam> a, b, result;
  UContextClear(a);
  UContextClear(b);
  UContextClear(result);
  memset(&b, 0xf1, 1);
  size_t baseline = UContextPopCount(b);

  UContextDiff(a, a, result);
  EXPECT_EQ(0, UContextPopCount(result));

  UContextDiff(a, b, result);
  EXPECT_EQ(baseline, UContextPopCount(result));

  UContextDiff(b, a, result);
  EXPECT_EQ(baseline, UContextPopCount(result));

  UContextDiff(b, b, result);
  EXPECT_EQ(0, UContextPopCount(result));
}

TYPED_TEST(UContextBitops, Toggle) {
  UContext<TypeParam> a, b, zero_one, one_zero;
  UContextClear(a);
  UContextClear(b);
  memset(&b, 0x3f, 1);
  size_t baseline = UContextPopCount(b);

  // a => b => a
  UContextClear(zero_one);
  UContextClear(one_zero);

  UContextAccumulateToggle(a, b, zero_one, one_zero);
  EXPECT_EQ(baseline, UContextPopCount(zero_one));
  EXPECT_EQ(0, UContextPopCount(one_zero));

  UContextAccumulateToggle(b, a, zero_one, one_zero);
  EXPECT_EQ(baseline, UContextPopCount(zero_one));
  EXPECT_EQ(baseline, UContextPopCount(one_zero));

  // b => a => b
  UContextClear(zero_one);
  UContextClear(one_zero);

  UContextAccumulateToggle(b, a, zero_one, one_zero);
  EXPECT_EQ(0, UContextPopCount(zero_one));
  EXPECT_EQ(baseline, UContextPopCount(one_zero));

  UContextAccumulateToggle(a, b, zero_one, one_zero);
  EXPECT_EQ(baseline, UContextPopCount(zero_one));
  EXPECT_EQ(baseline, UContextPopCount(one_zero));
}

}  // namespace
}  // namespace silifuzz
