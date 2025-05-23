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

#include <cstddef>
#include <cstdint>
#include <cstring>

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

TEST(BitopsLimit, PopCount) {
  TestStruct a;
  ClearBits(a);
  for (size_t limit = 1; limit <= sizeof(TestStruct); limit++) {
    size_t count = PopCount(&a, limit);
    EXPECT_EQ(count, 0);
  }

  memset(&a, 0xa5, 1);
  for (size_t limit = 1; limit <= sizeof(TestStruct); limit++) {
    size_t count = PopCount(&a, limit);
    EXPECT_EQ(count, 4);
  }

  memset(&a, 0xc4, sizeof(a));
  for (size_t limit = 1; limit <= sizeof(TestStruct); limit++) {
    size_t count = PopCount(&a, limit);
    EXPECT_EQ(count, PopCount(0xc4) * limit);
  }
}

TYPED_TEST(Bitops, PopCountArray) {
  TypeParam data[256];

  memset(data, 0x00, sizeof(data));

  memset(data, 0xf1, sizeof(data));
  EXPECT_EQ(5 * sizeof(data), PopCount(data));

  memset(data, 0xff, sizeof(data));
  EXPECT_EQ(8 * sizeof(data), PopCount(data));
}

TEST(BitopsLimit, PopCountArray) {
  uint16_t data[256];

  memset(data, 0x00, sizeof(data));
  for (size_t limit = 1; limit <= sizeof(data); limit++) {
    size_t count = PopCount(data, limit);
    EXPECT_EQ(count, 0);
  }

  memset(data, 0xf1, sizeof(data));
  for (size_t limit = 1; limit <= sizeof(data); limit++) {
    size_t count = PopCount(data, limit);
    EXPECT_EQ(count, 5 * limit);
  }

  memset(data, 0xff, sizeof(data));
  for (size_t limit = 1; limit <= sizeof(data); limit++) {
    size_t count = PopCount(data, limit);
    EXPECT_EQ(count, 8 * limit);
  }
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

TEST(Bitops2, Diff) {
  uint64_t a, b, result;
  ClearBits(a);
  ClearBits(b);
  ClearBits(result);

  // Set 1 byte
  memset(&b, 0xf1, 1);

  for (size_t limit = 1; limit <= sizeof(uint64_t); limit++) {
    BitDiff(&a, &b, limit, &result);
    EXPECT_EQ(PopCount(0xf1), PopCount(result));

    BitDiff(&b, &a, limit, &result);
    EXPECT_EQ(PopCount(0xf1), PopCount(result));

    BitDiff(&a, &a, limit, &result);
    EXPECT_EQ(0, PopCount(result));

    BitDiff(&b, &b, limit, &result);
    EXPECT_EQ(0, PopCount(result));
  }

  // Set all bytes
  memset(&b, 0x12, sizeof(b));
  for (size_t limit = 1; limit <= sizeof(uint64_t); limit++) {
    BitDiff(&a, &b, limit, &result);
    EXPECT_EQ(PopCount(0x12) * limit, PopCount(result));

    BitDiff(&b, &a, limit, &result);
    EXPECT_EQ(PopCount(0x12) * limit, PopCount(result));

    BitDiff(&a, &a, limit, &result);
    EXPECT_EQ(0, PopCount(result));

    BitDiff(&b, &b, limit, &result);
    EXPECT_EQ(0, PopCount(result));
  }
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

TEST(BitopsLimit, ToggleWithLimit) {
  uint64_t a, b, zero_one, one_zero;
  ClearBits(a);
  ClearBits(b);
  memset(&b, 0x3f, sizeof(b));
  for (size_t limit = 1; limit <= sizeof(uint64_t); limit++) {
    size_t baseline = PopCount(0x3f) * limit;
    // a => b => a
    ClearBits(zero_one);
    ClearBits(one_zero);

    AccumulateToggle(&a, &b, limit, &zero_one, &one_zero);
    EXPECT_EQ(baseline, PopCount(zero_one));
    EXPECT_EQ(0, PopCount(one_zero));

    AccumulateToggle(&b, &a, limit, &zero_one, &one_zero);
    EXPECT_EQ(baseline, PopCount(zero_one));
    EXPECT_EQ(baseline, PopCount(one_zero));

    // b => a => b
    ClearBits(zero_one);
    ClearBits(one_zero);

    AccumulateToggle(&b, &a, limit, &zero_one, &one_zero);
    EXPECT_EQ(0, PopCount(zero_one));
    EXPECT_EQ(baseline, PopCount(one_zero));

    AccumulateToggle(&a, &b, limit, &zero_one, &one_zero);
    EXPECT_EQ(baseline, PopCount(zero_one));
    EXPECT_EQ(baseline, PopCount(one_zero));
  }
}

TYPED_TEST(Bitops, ForEachBit) {
  TypeParam data;
  memset(&data, 0x20, sizeof(data));
  size_t zeros = 0;
  size_t ones = 0;
  size_t prev_index = (size_t)-1;
  ForEachBit(data, [&](size_t index, bool value) {
    // Check the index
    EXPECT_LT(index, NumBits<TypeParam>());
    EXPECT_EQ(index, prev_index + 1);
    prev_index = index;

    // Check the value
    if (value) {
      EXPECT_EQ(index % 8, 5);
      ones++;
    } else {
      zeros++;
    }
  });
  // Memsetting the data to 0x20 means that for every byte there should be a
  // single bit that's 1 and seven bits that are 0.
  EXPECT_EQ(sizeof(data) * 7, zeros) << "Expected seven 0 bits per byte";
  EXPECT_EQ(sizeof(data) * 1, ones) << "Expected one 1 bit per byte";
}

TEST(BitopsLimit, ForEachBitWithLimit) {
  uint64_t data;
  memset(&data, 0x20, sizeof(data));
  for (size_t limit = 1; limit <= sizeof(uint64_t); limit++) {
    size_t zeros = 0;
    size_t ones = 0;
    size_t prev_index = (size_t)-1;
    // The check in deeply nested loop may generate a lot of repeated errors and
    // blow up the error log. So we use ASSERT macros to stop the test early if
    // any error is found.
    ASSERT_NO_FATAL_FAILURE(
        ForEachBit(&data, limit, [&](size_t index, bool value) {
          // Check the index
          ASSERT_LT(index, NumBits<uint64_t>());
          ASSERT_EQ(index, prev_index + 1);
          prev_index = index;

          // Check the value
          if (value) {
            ASSERT_EQ(index % 8, 5);
            ones++;
          } else {
            zeros++;
          }
        }));
    // Memsetting the data to 0x20 means that for every byte there should be a
    // single bit that's 1 and seven bits that are 0.
    EXPECT_EQ(limit * 7, zeros) << "Expected seven 0 bits per byte";
    EXPECT_EQ(limit * 1, ones) << "Expected one 1 bit per byte";
  }
}

TYPED_TEST(Bitops, ForEachSetBit) {
  TypeParam data;
  memset(&data, 0x08, sizeof(data));
  size_t count = 0;
  size_t prev_index = (size_t)-1;
  ForEachSetBit(data, [&](size_t index) {
    // Index in range
    EXPECT_LT(index, NumBits<TypeParam>());
    // Index is at an expected stride
    EXPECT_EQ(index % 8, 3);
    // Index is increasing monotonically
    EXPECT_GT(index - prev_index, 0);
    prev_index = index;
    count++;
  });
  // There should be a single bit set per byte.
  EXPECT_EQ(sizeof(data), count) << "Expected one 1 bit per byte";
}

TEST(BitopsLimit, ForEachSetBitWithLimit) {
  uint64_t data;
  memset(&data, 0x08, sizeof(data));
  for (size_t limit = 1; limit <= sizeof(uint64_t); limit++) {
    size_t count = 0;
    size_t prev_index = (size_t)-1;
    // The check in deeply nested loop may generate a lot of repeated errors and
    // blow up the error log. So we use ASSERT macros to stop the test early if
    // any error is found.
    ASSERT_NO_FATAL_FAILURE(ForEachSetBit(&data, limit, [&](size_t index) {
      // Index in range
      ASSERT_LT(index, NumBits<uint64_t>());
      // Index is at an expected stride
      ASSERT_EQ(index % 8, 3);
      // Index is increasing monotonically
      ASSERT_GT(index - prev_index, 0);
      prev_index = index;
      count++;
    }));
    // There should be a single bit set per byte.
    EXPECT_EQ(limit, count) << "Expected one 1 bit per byte";
  }
}

TYPED_TEST(Bitops, ForEachDiffBit) {
  TypeParam a, b;
  memset(&a, 0xf0, sizeof(a));
  memset(&b, 0xe1, sizeof(b));
  size_t zeros = 0;
  size_t ones = 0;
  size_t prev_index = (size_t)-1;
  ForEachDiffBit(a, b, [&](size_t index, bool value) {
    // Index in range
    EXPECT_LT(index, NumBits<TypeParam>());
    // Index is increasing monotonically
    EXPECT_GT(index - prev_index, 0);
    prev_index = index;
    // Index is at an expected stride
    if (value) {
      EXPECT_EQ(index % 8, 0);
      ones++;
    } else {
      EXPECT_EQ(index % 8, 4);
      zeros++;
    }
  });
  // Two bits should differ for every byte - in "b" one of those bits should be
  // 0 and the other should be 1. ( 0xf0 ^ 0xe1 == 0x11 / 0xe1 & 0x11 == 0x01)
  EXPECT_EQ(sizeof(TypeParam), zeros);
  EXPECT_EQ(sizeof(TypeParam), ones);
}

TEST(BitopsLimit, ForEachDiffBitWithLimit) {
  uint64_t a, b;
  memset(&a, 0xf0, sizeof(a));
  memset(&b, 0xe1, sizeof(b));
  for (size_t limit = 1; limit <= sizeof(uint64_t); limit++) {
    size_t zeros = 0;
    size_t ones = 0;
    size_t prev_index = (size_t)-1;
    // The check in deeply nested loop may generate a lot of repeated errors and
    // blow up the error log. So we use ASSERT macros to stop the test early if
    // any error is found.
    ASSERT_NO_FATAL_FAILURE(
        ForEachDiffBit(&a, &b, limit, [&](size_t index, bool value) {
          // Index in range
          ASSERT_LT(index, NumBits<uint64_t>());
          // Index is increasing monotonically
          ASSERT_GT(index - prev_index, 0);
          prev_index = index;
          // Index is at an expected stride
          if (value) {
            ASSERT_EQ(index % 8, 0);
            ones++;
          } else {
            ASSERT_EQ(index % 8, 4);
            zeros++;
          }
        }));
    // Two bits should differ for every byte - in "b" one of those bits should
    // be 0 and the other should be 1. ( 0xf0 ^ 0xe1 == 0x11 / 0xe1 & 0x11 ==
    // 0x01)
    EXPECT_EQ(limit, zeros);
    EXPECT_EQ(limit, ones);
  }
}

}  // namespace
}  // namespace silifuzz
