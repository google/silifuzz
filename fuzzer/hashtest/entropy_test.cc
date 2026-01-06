// Copyright 2026 The Silifuzz Authors.
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

#include "./fuzzer/hashtest/entropy.h"

#include <cstddef>
#include <cstdint>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace {

TEST(EntropyTest, FormatSeedTest) {
  uint64_t seed = 0xABCDEF;
  EXPECT_EQ(silifuzz::FormatSeed(seed), "0000000000abcdef");
}

TEST(EntropyTest, RandomyEntropyBufferTest) {
  silifuzz::EntropyBuffer buffer;
  silifuzz::RandomizeEntropyBuffer(0, buffer);
  silifuzz::EntropyBuffer buffer2;
  silifuzz::RandomizeEntropyBuffer(1, buffer2);

  bool different = false;
  for (size_t i = 0; !different && i < silifuzz::kEntropyBytes512; ++i) {
    different = different || buffer.bytes[i] != buffer2.bytes[i];
  }

  EXPECT_THAT(different, testing::IsTrue());
}

}  // namespace
