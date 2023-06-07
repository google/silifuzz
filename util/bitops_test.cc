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

#include "./util/bitops.h"

#include <cstdint>

#include "gtest/gtest.h"

namespace silifuzz {
namespace {

template <class>
struct Bitops : testing::Test {};

struct TestStruct {
  uint8_t data[1024];
};

using arch_typelist = testing::Types<uint8_t, uint16_t, uint32_t, uint64_t,
                                     __uint128_t, TestStruct>;
TYPED_TEST_SUITE(Bitops, arch_typelist);

TYPED_TEST(Bitops, PopCount) {
  TypeParam a;
  ClearBits(a);
  EXPECT_EQ(0, PopCount(a));

  memset(&a, 0xa5, 1);
  EXPECT_EQ(4, PopCount(a));

  memset(&a, 0xc4, sizeof(a));
  EXPECT_EQ(sizeof(a) * 3, PopCount(a));
}

TYPED_TEST(Bitops, PopCountArray) {
  TypeParam data[256];

  memset(data, 0x00, sizeof(data));
  EXPECT_EQ(0, PopCount(data));

  memset(data, 0xf1, sizeof(data));
  EXPECT_EQ(5 * sizeof(data), PopCount(data));

  memset(data, 0xff, sizeof(data));
  EXPECT_EQ(8 * sizeof(data), PopCount(data));
}

TYPED_TEST(Bitops, Diff) {
  TypeParam a, b, result;
  ClearBits(a);
  ClearBits(b);
  ClearBits(result);

  // Set 1 byte
  memset(&b, 0xf1, 1);
  size_t baseline = PopCount(b);

  BitDiff(a, a, result);
  EXPECT_EQ(0, PopCount(result));

  BitDiff(a, b, result);
  EXPECT_EQ(baseline, PopCount(result));

  BitDiff(b, a, result);
  EXPECT_EQ(baseline, PopCount(result));

  BitDiff(b, b, result);
  EXPECT_EQ(0, PopCount(result));

  // Set all bytes
  memset(&b, 0x12, sizeof(b));
  baseline = PopCount(b);

  BitDiff(a, a, result);
  EXPECT_EQ(0, PopCount(result));

  BitDiff(a, b, result);
  EXPECT_EQ(baseline, PopCount(result));

  BitDiff(b, a, result);
  EXPECT_EQ(baseline, PopCount(result));

  BitDiff(b, b, result);
  EXPECT_EQ(0, PopCount(result));
}

TYPED_TEST(Bitops, Toggle) {
  TypeParam a, b, zero_one, one_zero;
  ClearBits(a);
  ClearBits(b);
  memset(&b, 0x3f, 1);
  size_t baseline = PopCount(b);

  // a => b => a
  ClearBits(zero_one);
  ClearBits(one_zero);

  AccumulateToggle(a, b, zero_one, one_zero);
  EXPECT_EQ(baseline, PopCount(zero_one));
  EXPECT_EQ(0, PopCount(one_zero));

  AccumulateToggle(b, a, zero_one, one_zero);
  EXPECT_EQ(baseline, PopCount(zero_one));
  EXPECT_EQ(baseline, PopCount(one_zero));

  // b => a => b
  ClearBits(zero_one);
  ClearBits(one_zero);

  AccumulateToggle(b, a, zero_one, one_zero);
  EXPECT_EQ(0, PopCount(zero_one));
  EXPECT_EQ(baseline, PopCount(one_zero));

  AccumulateToggle(a, b, zero_one, one_zero);
  EXPECT_EQ(baseline, PopCount(zero_one));
  EXPECT_EQ(baseline, PopCount(one_zero));
}

}  // namespace
}  // namespace silifuzz
