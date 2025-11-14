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

#include "./fuzzer/hashtest/testgeneration/weighted_choose_one.h"

#include <cstddef>
#include <random>

#include "gtest/gtest.h"

namespace silifuzz {

namespace {

TEST(WeightedChooseOne, Single) {
  std::mt19937_64 rng(0);
  size_t a = 0;
  constexpr size_t kNumIter = 40000;
  for (size_t i = 0; i < kNumIter; i++) {
    EXPECT_EQ(WeightedChooseOne(rng,
                                WeightedChoice{
                                    1,
                                    [&] {
                                      a += 1;
                                      return 11;
                                    },
                                }),
              11);
  }
  EXPECT_EQ(a, kNumIter);
}

TEST(WeightedChooseOne, Zero) {
  std::mt19937_64 rng(0);
  size_t a = 0;
  size_t b = 0;
  constexpr size_t kNumIter = 40000;
  for (size_t i = 0; i < kNumIter; i++) {
    WeightedChooseOne(rng,
                      // A
                      WeightedChoice{
                          1,
                          [&] { a += 1; },
                      },
                      // B
                      WeightedChoice{
                          0,
                          [&] { b += 1; },
                      });
  }
  EXPECT_EQ(a, kNumIter);
  EXPECT_EQ(b, 0);
}

TEST(WeightedChooseOne, CheckWeights) {
  std::mt19937_64 rng(0);
  size_t a = 0;
  size_t b = 0;
  size_t c = 0;
  size_t d = 0;
  constexpr size_t kNumIter = 40000;
  constexpr int kAWeight = 1;
  constexpr int kBWeight = 2;
  constexpr int kCWeight = 3;
  constexpr int kDWeight = 4;
  constexpr int kTotalWeight = kAWeight + kBWeight + kCWeight + kDWeight;
  for (size_t i = 0; i < kNumIter; i++) {
    WeightedChooseOne(rng,
                      // A
                      WeightedChoice{
                          kAWeight,
                          [&] { a += 1; },
                      },
                      // B
                      WeightedChoice{
                          kBWeight,
                          [&] { b += 1; },
                      },
                      // C
                      WeightedChoice{
                          kCWeight,
                          [&] { c += 1; },
                      },
                      // D
                      WeightedChoice{
                          kDWeight,
                          [&] { d += 1; },
                      });
  }
  // Assert that we are not more than 5% off the expected distribution.
  // It's questionable to test random behavior, but this is somewhat forgiven
  // by having a fixed seed.
  constexpr auto lower_limit = [&](int weight) -> size_t {
    return kNumIter * weight * 95 / 100 / kTotalWeight;
  };
  EXPECT_GE(a, lower_limit(kAWeight));
  EXPECT_GE(b, lower_limit(kBWeight));
  EXPECT_GE(c, lower_limit(kCWeight));
  EXPECT_GE(d, lower_limit(kDWeight));
}

}  // namespace
}  // namespace silifuzz
