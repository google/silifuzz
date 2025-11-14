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

#include "./fuzzer/hashtest/testgeneration/rand_util.h"

#include <bitset>
#include <cstddef>
#include <random>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace silifuzz {

namespace {

using ::testing::UnorderedElementsAre;

TEST(RandUtil, SingleRandomBit) {
  std::mt19937_64 rng(0);
  constexpr size_t kNumBits = 100;
  for (size_t i = 0; i < kNumBits; ++i) {
    std::bitset<kNumBits> bits;
    bits.set(i);
    EXPECT_TRUE(bits.any());
    EXPECT_EQ(i, ChooseRandomBit(rng, bits));
    EXPECT_TRUE(bits.any());
    EXPECT_EQ(i, PopRandomBit(rng, bits));
    EXPECT_FALSE(bits.any());
  }
}

TEST(RandUtil, MultipleRandomBits) {
  std::mt19937_64 rng(0);
  constexpr size_t kNumBits = 100;
  std::bitset<kNumBits> bits;
  bits.set(11);
  bits.set(13);
  bits.set(53);
  bits.set(97);
  std::vector<size_t> popped_bits;
  while (bits.any()) {
    popped_bits.push_back(PopRandomBit(rng, bits));
  }
  EXPECT_THAT(popped_bits, UnorderedElementsAre(11, 13, 53, 97));
}

TEST(RandUtil, RandomElementVec) {
  std::mt19937_64 rng(0);
  std::vector<int> v = {7};
  EXPECT_EQ(7, ChooseRandomElement(rng, v));
}

TEST(RandUtil, RandomElementInitList) {
  std::mt19937_64 rng(0);
  EXPECT_EQ(11, ChooseRandomElement(rng, {11}));
}

}  // namespace
}  // namespace silifuzz
