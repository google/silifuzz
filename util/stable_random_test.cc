// Copyright 2026 The SiliFuzz Authors.
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
//
#include "./util/stable_random.h"

#include <random>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace silifuzz {
namespace tpu {
namespace {

using ::testing::ElementsAre;
using ::testing::SizeIs;

TEST(StableRandomTest, StableUniformSizeT) {
  std::mt19937_64 rng(12345);
  EXPECT_EQ(StableUniformSizeT(0, 0, rng), 0);
  std::mt19937_64 rng1(12345);
  std::mt19937_64 rng2(12345);
  for (int i = 0; i < 10; ++i) {
    EXPECT_EQ(StableUniformSizeT(0, 100, rng1),
              StableUniformSizeT(0, 100, rng2));
  }
}

TEST(StableRandomTest, StableShuffle) {
  std::mt19937_64 rng(54321);
  std::vector<int> v = {0, 1, 2, 3, 4, 5, 6, 7};
  StableShuffle(v, rng);
  EXPECT_THAT(v, SizeIs(8));
  // With seed 54321, we expect a specific shuffle result.
  // If StableShuffle changes, this test will fail.
  // The expected result is obtained by running the test and recording
  // the shuffled result.
  EXPECT_THAT(v, ElementsAre(1, 7, 4, 6, 5, 3, 0, 2));

  std::mt19937_64 rng1(54321);
  std::vector<int> v1 = {0, 1, 2, 3, 4, 5, 6, 7};
  StableShuffle(v1, rng1);
  EXPECT_EQ(v, v1);
}

TEST(StableRandomTest, StableShuffleEmpty) {
  std::mt19937_64 rng(1);
  std::vector<int> v;
  StableShuffle(v, rng);
  EXPECT_THAT(v, SizeIs(0));
}

}  // namespace
}  // namespace tpu
}  // namespace silifuzz
