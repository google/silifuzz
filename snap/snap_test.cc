// Copyright 2022 The SiliFuzz Authors.
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

#include "./snap/snap.h"

#include "gtest/gtest.h"

namespace silifuzz {
namespace {

TEST(Snap, ConstIterator) {
  SnapArray<int> empty = {.size = 0, .elements = nullptr};
  EXPECT_EQ(empty.begin(), empty.end());

  constexpr int kElements[] = {1, 1, 2, 3, 5, 8};
  constexpr int kNumElements = sizeof(kElements) / sizeof(kElements[0]);
  SnapArray<int> array = {.size = kNumElements, .elements = kElements};

  int i = 0;
  for (const auto& element : array) {
    EXPECT_EQ(element, kElements[i]);
    i++;
  }
  EXPECT_EQ(i, kNumElements);
}

}  // namespace
}  // namespace silifuzz
