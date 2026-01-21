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

#include "./fuzzer/hashtest/runnable_corpus.h"

#include <array>
#include <cstddef>
#include <cstdint>

#include "gtest/gtest.h"

namespace silifuzz {
namespace {

constexpr size_t kAllocationSize = kMaxTestBytes * 100;

TEST(RunnableCorpusTest, GetTestLengthBasic) {
  std::array<uint8_t, kAllocationSize> allocation;
  allocation.fill(0);

  // Set fake data in range [kMaxTestBytes, 1.5*kMaxTestBytes]
  constexpr size_t kTestLength = kMaxTestBytes / 2;
  constexpr size_t kTestStartIndex = kMaxTestBytes;
  for (int i = kTestStartIndex; i < kTestStartIndex + kTestLength; ++i) {
    allocation[i] = 1;
  }

  EXPECT_EQ(kTestLength, GetTestLength(&allocation[kTestStartIndex],
                                       allocation.data(), kAllocationSize));
}
TEST(RunnableCorpusTest, GetTestLengthAliasingForFirstTest) {
  std::array<uint8_t, kAllocationSize> allocation;
  allocation.fill(0);

  constexpr size_t kTestLength = kMaxTestBytes / 2;
  constexpr size_t kTestStartIndex = 0;
  for (int i = kTestStartIndex; i < kTestLength; ++i) {
    allocation[i] = 1;
  }

  EXPECT_EQ(kTestLength, GetTestLength(allocation.data(), allocation.data(),
                                       kAllocationSize));
}
TEST(RunnableCorpusTest, GetTestLengthEndOfAllocation) {
  std::array<uint8_t, kAllocationSize> allocation;
  allocation.fill(0);

  constexpr size_t kTestLength = kMaxTestBytes / 2;
  constexpr size_t kTestStartIndex = kAllocationSize - kTestLength;
  for (int i = kTestStartIndex; i < kAllocationSize; ++i) {
    allocation[i] = 1;
  }

  EXPECT_EQ(kTestLength, GetTestLength(&allocation[kTestStartIndex],
                                       allocation.data(), kAllocationSize));
}
TEST(RunnableCorpusTest, GetTestLength64BitZeroConstantInMiddle) {
  std::array<uint8_t, kAllocationSize> allocation;
  allocation.fill(0);

  // Set fake data in range [kMaxTestBytes, 1.5*kMaxTestBytes]
  constexpr size_t kTestLength = kMaxTestBytes / 2;
  constexpr size_t kTestStartIndex = kMaxTestBytes;
  for (int i = kTestStartIndex; i < kTestStartIndex + kTestLength; ++i) {
    allocation[i] = 1;
  }

  constexpr size_t kConstantsOffset = kTestStartIndex + 10;
  for (int i = 0; i < 8; ++i) {
    allocation[kConstantsOffset + i] = 0;
  }

  EXPECT_EQ(kTestLength, GetTestLength(&allocation[kTestStartIndex],
                                       allocation.data(), kAllocationSize));
}

}  // namespace
}  // namespace silifuzz
