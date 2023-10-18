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

#include "./common/snapshot_test_enum.h"

#include <stddef.h>

#include <iterator>

#include "gtest/gtest.h"
#include "./util/itoa.h"

namespace silifuzz {

namespace {

TEST(SnapshotTestEnum, Complete) {
  // Array initializers will initialize missing elements to nullptr.
  // It's easy to overlook that you need to update the EnumNameMap when you
  // modify the TestSnapshot enum. Look for any nullptr.
  for (size_t i = 0; i < std::size(EnumNameMap<TestSnapshot>); ++i) {
    EXPECT_NE(EnumNameMap<TestSnapshot>[i], nullptr) << i;
  }
}

TEST(SnapshotTestEnum, EnumStr) {
  // Spot checks to ensure there's no obvious off-by-ones.
  EXPECT_STREQ(EnumStr(TestSnapshot::kEmpty), "kEmpty");
  EXPECT_STREQ(EnumStr(TestSnapshot::kSigIll), "kSigIll");
  EXPECT_STREQ(EnumStr(TestSnapshot::kSplitLock), "kSplitLock");
}

}  // namespace

}  // namespace silifuzz
