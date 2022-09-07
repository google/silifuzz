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

#include "./common/mapped_memory_map.h"

#include <optional>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"

namespace silifuzz {
namespace {

class MappedMemoryMapTest : public testing::Test {
 public:
  using Address = MappedMemoryMap::Address;

  // Like MappedMemoryMap::DebugString() but uses int, not hex, values of
  // the addresses (also separator is just the space).
  std::string IntDebugString(const MappedMemoryMap& m) {
    std::string r;
    m.Iterate([&r](Address start, Address limit, MemoryPerms perms) {
      absl::StrAppend(&r, start, "..", limit, ":", perms.DebugString(), " ");
    });
    return r;
  }

  // A version of IntDebugString() for MemoryMapping. This is used in
  // MappingAt() test.
  std::string IntDebugString(const MemoryMapping& m) {
    return absl::StrCat(m.start_address(), "..", m.limit_address(), ":",
                        m.perms().DebugString());
  }

  const MemoryPerms zero_perms = MemoryPerms::None();
  const MemoryPerms no_perms = zero_perms.Plus(MemoryPerms::kMapped);
  const MemoryPerms r_perms = MemoryPerms::R().Plus(MemoryPerms::kMapped);
  const MemoryPerms w_perms = MemoryPerms::W().Plus(MemoryPerms::kMapped);
  const MemoryPerms x_perms = MemoryPerms::X().Plus(MemoryPerms::kMapped);
  const MemoryPerms rw_perms = MemoryPerms::RW().Plus(MemoryPerms::kMapped);
  const MemoryPerms rx_perms = MemoryPerms::XR().Plus(MemoryPerms::kMapped);
  const MemoryPerms rwx_perms = MemoryPerms::RWX().Plus(MemoryPerms::kMapped);
};

// Most of MappedMemoryMap is a thin wrapper around a class with its own proper
// tests, so we do some basic tests for those to exercise things and make sure
// we don't have simple bugs like a misplaced negation.
TEST_F(MappedMemoryMapTest, Basics) {
  MappedMemoryMap m;
  EXPECT_TRUE(m.IsEmpty());
  m.AddNew(100, 150, rw_perms);
  m.AddNew(150, 250, r_perms);
  EXPECT_FALSE(m.IsEmpty());
  m.Add(100, 300, w_perms);
  m.Set(200, 300, x_perms);
  m.Remove(180, 220);
  m.AddNew(350, 400, no_perms);
  // Since no_perms actually contains MemoryPerms::kMapped, we are
  // removing that record from the map here:
  m.Remove(390, 410, no_perms);
  EXPECT_FALSE(m.IsEmpty());

  // This also tests Iterate():
  EXPECT_EQ(IntDebugString(m), "100..180:rw-m 220..300:--xm 350..390:---m ");

  auto copy = m.Copy();
  EXPECT_TRUE(copy == m);
  EXPECT_FALSE(copy != m);
  copy.Remove(260, 261);
  EXPECT_FALSE(copy == m);
  EXPECT_TRUE(copy != m);
  copy.Clear();
  EXPECT_TRUE(copy.IsEmpty());

  EXPECT_TRUE(m.Contains(150));
  EXPECT_TRUE(m.Contains(375));
  EXPECT_FALSE(m.Contains(200));
  EXPECT_FALSE(m.Contains(50));

  EXPECT_EQ(m.PermsAt(50), zero_perms);
  EXPECT_EQ(m.PermsAt(150), rw_perms);
  EXPECT_EQ(m.PermsAt(200), zero_perms);
  EXPECT_EQ(m.PermsAt(230), x_perms);
  EXPECT_EQ(m.PermsAt(260), x_perms);
  EXPECT_EQ(m.PermsAt(375), no_perms);
  EXPECT_EQ(m.PermsAt(600), zero_perms);

  EXPECT_TRUE(m.Contains(100, 180));
  EXPECT_TRUE(m.Contains(260, 280));
  EXPECT_FALSE(m.Contains(260, 301));
  EXPECT_TRUE(m.Contains(360, 380));
  EXPECT_FALSE(m.Contains(360, 401));

  EXPECT_TRUE(m.Overlaps(100, 180));
  EXPECT_TRUE(m.Overlaps(50, 101));
  EXPECT_FALSE(m.Overlaps(50, 100));

  // Perms(), RemoveRangesOf(), AddIntersectionOf(), and AddDifferenceOf()
  // are all tested below separately.

  EXPECT_EQ(m.DebugString(),
            "0x64..0xb4:rw-m, 0xdc..0x12c:--xm, 0x15e..0x186:---m, ");
}

// Perms() test is most involved (has non-trivial impl):
TEST_F(MappedMemoryMapTest, Perms) {
  const auto kOr = MemoryPerms::kOr;
  const auto kAnd = MemoryPerms::kAnd;

  MappedMemoryMap m;
  // A simple ordered setup for `m` that directly describes its resulting state:
  m.AddNew(3, 5, r_perms);
  m.AddNew(10, 20, rw_perms);
  m.AddNew(20, 30, rx_perms);
  m.AddNew(35, 40, x_perms);
  m.AddNew(40, 45, no_perms);
  m.AddNew(45, 50, r_perms);
  m.AddNew(101, 102, r_perms);
  EXPECT_EQ(IntDebugString(m),
            "3..5:r--m 10..20:rw-m 20..30:r-xm 35..40:--xm "
            "40..45:---m 45..50:r--m 101..102:r--m ");

  // Within one range.
  EXPECT_EQ(m.Perms(11, 19, kOr), rw_perms);
  EXPECT_EQ(m.Perms(10, 20, kAnd), rw_perms);

  // Before all known ranges.
  EXPECT_EQ(m.Perms(0, 3, kOr), zero_perms);

  // Fully within a gap.
  EXPECT_EQ(m.Perms(30, 34, kOr), zero_perms);
  // After all known ranges.
  EXPECT_EQ(m.Perms(1000, 2000, kOr), zero_perms);

  // Starting before a range and/or spanning two adjacent ranges.
  EXPECT_EQ(m.Perms(9, 21, kOr), rwx_perms);
  EXPECT_EQ(m.Perms(9, 21, kAnd), zero_perms);
  EXPECT_EQ(m.Perms(10, 21, kAnd), r_perms);

  // Ending after a range and/or spanning two adjacent ranges.
  EXPECT_EQ(m.Perms(19, 31, kOr), rwx_perms);
  EXPECT_EQ(m.Perms(19, 31, kAnd), zero_perms);
  EXPECT_EQ(m.Perms(19, 30, kAnd), r_perms);

  // Spanning over gaps:
  EXPECT_EQ(m.Perms(25, 40, kOr), rx_perms);
  EXPECT_EQ(m.Perms(25, 40, kAnd), zero_perms);

  // Spanning over explicit no_perms:
  EXPECT_EQ(m.Perms(36, 50, kOr), rx_perms);
  EXPECT_EQ(m.Perms(36, 50, kAnd), no_perms);

  // Spanning over multiple ranges:
  EXPECT_EQ(m.Perms(9, 51, kOr), rwx_perms);
  EXPECT_EQ(m.Perms(10, 40, kOr), rwx_perms);
  EXPECT_EQ(m.Perms(11, 39, kOr), rwx_perms);
  EXPECT_EQ(m.Perms(10, 40, kAnd), zero_perms);
}

// RemoveRangesOf(), AddIntersectionOf(), and AddDifferenceOf() are mostly
// thin wrappers but use our MemoryPermsMethods helpers, so we test them but
// not too heavily:
TEST_F(MappedMemoryMapTest, Complex) {
  // Test RemoveRangesOf():

  MappedMemoryMap m1;
  m1.AddNew(10, 20, no_perms);
  m1.AddNew(30, 40, rw_perms);
  m1.AddNew(44, 46, r_perms);
  m1.AddNew(50, 60, rx_perms);
  EXPECT_EQ(IntDebugString(m1),
            "10..20:---m 30..40:rw-m 44..46:r--m 50..60:r-xm ");

  MappedMemoryMap m2;
  m2.AddNew(13, 15, no_perms);
  m2.AddNew(15, 33, w_perms);
  m2.AddNew(37, 53, r_perms);
  EXPECT_EQ(IntDebugString(m2), "13..15:---m 15..33:-w-m 37..53:r--m ");

  MappedMemoryMap mr = m1.Copy();
  mr.RemoveRangesOf(m2, r_perms);
  // All the ranges of m2 in m1 where perms become (or were empty) are removed:
  // 13..15, 15..20, and 44..46, while 10..13 stays with no_perms because
  // it's not in m2.
  EXPECT_EQ(IntDebugString(mr),
            "10..13:---m 30..33:-w-- 33..37:rw-m "
            "37..40:-w-- 50..53:--x- 53..60:r-xm ");

  // Test AddIntersectionOf():

  mr.Clear();
  mr.AddIntersectionOf(m1, m2);
  // Note that 13..20 makes it: it's present with empty rwx perms in m1 and m2,
  // but kMapped perm is set there:
  EXPECT_EQ(IntDebugString(mr),
            "13..20:---m 30..33:-w-m 37..40:r--m 44..46:r--m 50..53:r--m ");

  MappedMemoryMap mr2;
  // AddIntersectionOf() is symmetrical:
  mr2.AddIntersectionOf(m2, m1);
  EXPECT_EQ(mr, mr2);

  // Test AddDifferenceOf():
  mr.Clear();
  mr.AddDifferenceOf(15, 55, r_perms, m1);
  // Note that 30..40 and 50..55 remain with empty perms because perms in m1
  // were != r_perms but larger for those ranges, while 44..46 where m1 had
  // exactly r_perms is completely removed:
  // Note that 15..30 range is split at 20 because 15..20 gets the kMapped
  // perm removed:
  EXPECT_EQ(IntDebugString(mr),
            "15..20:r--- 20..30:r--m 30..40:---- "
            "40..44:r--m 46..50:r--m 50..55:---- ");

  // Test the map-map version of AddDifferenceOf():
  mr.Clear();
  mr.AddDifferenceOf(m1, m2);
  EXPECT_EQ(IntDebugString(mr),
            "10..13:---m 15..20:---- 30..33:r--- 33..37:rw-m "
            "37..40:-w-- 50..53:--x- 53..60:r-xm ");
}

TEST_F(MappedMemoryMapTest, MappingAt) {
  MappedMemoryMap m;
  m.AddNew(3, 5, r_perms);

  // The two should be merged into a single mapping.
  m.AddNew(10, 20, rw_perms);
  m.Add(15, 25, rw_perms);

  auto mapping1 = m.MappingAt(1);
  EXPECT_EQ(mapping1, std::nullopt);

  auto mapping2 = m.MappingAt(4);
  ASSERT_TRUE(mapping2.has_value());
  EXPECT_EQ(IntDebugString(mapping2.value()), "3..5:r---");

  auto mapping3 = m.MappingAt(20);
  ASSERT_TRUE(mapping3.has_value());
  EXPECT_EQ(IntDebugString(mapping3.value()), "10..25:rw--");
}

}  // namespace
}  // namespace silifuzz
