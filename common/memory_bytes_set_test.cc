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

#include "./common/memory_bytes_set.h"

#include <string>

#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"

namespace silifuzz {
namespace {

class MemoryBytesSetTest : public testing::Test {
 public:
  using Address = MemoryBytesSet::Address;

  // Like MemoryBytesSet::DebugString() but uses int, not hex, values of
  // the addresses (also separator is just the space).
  std::string IntDebugString(const MemoryBytesSet& m) {
    std::string r;
    m.Iterate([&r](Address start, Address limit) {
      absl::StrAppend(&r, start, "..", limit, " ");
    });
    return r;
  }
};

// Most of MemoryBytesSet is a thin wrapper around a class with its own proper
// tests, so we do some basic tests for those to exercise things and make sure
// we don't have simple bugs like a misplaced negation.
TEST_F(MemoryBytesSetTest, Basics) {
  MemoryBytesSet m;
  EXPECT_TRUE(m.empty());
  EXPECT_EQ(m.size(), 0);
  EXPECT_EQ(m.byte_size(), 0);

  m.Add(100, 150);
  m.Add(150, 250);
  EXPECT_FALSE(m.empty());
  EXPECT_EQ(m.size(), 1);
  EXPECT_EQ(m.byte_size(), 150);

  m.Add(100, 300);
  m.Remove(180, 220);
  m.Add(350, 400);
  m.Remove(390, 410);
  EXPECT_FALSE(m.empty());
  EXPECT_EQ(m.size(), 3);
  EXPECT_EQ(m.byte_size(), 200);

  // This also tests Iterate():
  EXPECT_EQ(IntDebugString(m), "100..180 220..300 350..390 ");

  // Test compare operators.
  auto copy = m;
  EXPECT_TRUE(copy.operator==(m));
  EXPECT_FALSE(copy.operator!=(m));
  copy.Remove(260, 261);
  EXPECT_FALSE(copy.operator==(m));
  EXPECT_TRUE(copy.operator!=(m));
  copy.clear();
  EXPECT_TRUE(copy.empty());

  EXPECT_FALSE(m.IsDisjoint(100, 180));
  EXPECT_FALSE(m.IsDisjoint(50, 101));
  EXPECT_TRUE(m.IsDisjoint(50, 100));
}

TEST_F(MemoryBytesSetTest, Intersect) {
  MemoryBytesSet m1;
  m1.Add(10, 20);
  m1.Add(30, 40);
  EXPECT_EQ(IntDebugString(m1), "10..20 30..40 ");

  MemoryBytesSet m2;
  m2.Add(15, 25);
  m2.Add(35, 45);
  EXPECT_EQ(IntDebugString(m2), "15..25 35..45 ");

  m1.Intersect(m2);
  EXPECT_EQ(IntDebugString(m1), "15..20 35..40 ");
}

}  // namespace
}  // namespace silifuzz
