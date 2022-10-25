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

#include "./tool_libs/snap_group.h"

#include <sys/mman.h>

#include <cstddef>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "./common/mapped_memory_map.h"
#include "./common/snapshot_test_util.h"
#include "./util/testing/status_macros.h"
#include "./util/testing/status_matchers.h"

namespace silifuzz {
namespace {

using ::silifuzz::testing::StatusIs;
using ::testing::Contains;
using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::Not;

constexpr size_t kNumMappings1 = 2;
const Snap::MemoryMapping kMemoryMappings1[kNumMappings1] = {
    {.start_address = 0x1234000ULL,
     .num_bytes = 0x4000,
     .perms = PROT_READ | PROT_EXEC},
    {.start_address = 0x5678000ULL,
     .num_bytes = 0x1000,
     .perms = PROT_READ | PROT_WRITE},
};

const Snap kSnap1{
    .id = "snap1",
    .memory_mappings =
        {
            .size = kNumMappings1,
            .elements = kMemoryMappings1,
        },
};

// No conflict with kSnap1.
constexpr size_t kNumMappings2 = 2;
const Snap::MemoryMapping kMemoryMappings2[kNumMappings2] = {
    {.start_address = 0x3456000ULL,
     .num_bytes = 0x4000,
     .perms = PROT_READ | PROT_EXEC},
    {.start_address = 0x789a000ULL,
     .num_bytes = 0x1000,
     .perms = PROT_READ | PROT_WRITE},
};

const Snap kSnap2{
    .id = "snap2",
    .memory_mappings =
        {
            .size = kNumMappings2,
            .elements = kMemoryMappings2,
        },
};

// Read-only mapping conflict with kSnap1
constexpr size_t kNumMappings3 = 2;
const Snap::MemoryMapping kMemoryMappings3[kNumMappings3] = {
    {.start_address = 0x1234000ULL,
     .num_bytes = 0x4000,
     .perms = PROT_READ | PROT_EXEC},
    {.start_address = 0x6789000ULL,
     .num_bytes = 8192,
     .perms = PROT_READ | PROT_WRITE},
};

const Snap kSnap3{
    .id = "snap3",
    .memory_mappings =
        {
            .size = kNumMappings3,
            .elements = kMemoryMappings3,
        },
};

// Writable mapping conflict with kSnap1, same permissions.
constexpr size_t kNumMappings4 = 2;
const Snap::MemoryMapping kMemoryMappings4[kNumMappings4] = {
    {.start_address = 0x2345000ULL,
     .num_bytes = 0x4000,
     .perms = PROT_READ | PROT_EXEC},
    {.start_address = 0x5678000ULL,
     .num_bytes = 0x1000,
     .perms = PROT_READ | PROT_WRITE},
};

const Snap kSnap4{
    .id = "snap4",
    .memory_mappings =
        {
            .size = kNumMappings4,
            .elements = kMemoryMappings4,
        },
};

// Writable mapping conflict with kSnap1, different permissions.
// Read-only conflict with kSnap2.
constexpr size_t kNumMappings5 = 2;
const Snap::MemoryMapping kMemoryMappings5[kNumMappings5] = {
    {.start_address = 0x3456000ULL,
     .num_bytes = 0x4000,
     .perms = PROT_READ | PROT_EXEC},
    {.start_address = 0x5678000ULL,
     .num_bytes = 0x1000,
     .perms = PROT_READ | PROT_WRITE | PROT_EXEC},
};

const Snap kSnap5{
    .id = "snap5",
    .memory_mappings =
        {
            .size = kNumMappings5,
            .elements = kMemoryMappings5,
        },
};

TEST(SnapshotSummary, ConstructFromSnapshot) {
  Snapshot snapshot = TestSnapshots::Create(TestSnapshots::kEndsAsExpected);
  SnapshotGroup::SnapshotSummary memory_summary(snapshot);
  EXPECT_EQ(memory_summary.id(), snapshot.id());
  EXPECT_EQ(memory_summary.memory_mappings(), snapshot.memory_mappings());
}

TEST(SnapshotSummary, ConstructFromSnap) {
  SnapshotGroup::SnapshotSummary memory_summary(kSnap1);
  EXPECT_EQ(memory_summary.id(), kSnap1.id);
  ASSERT_EQ(memory_summary.memory_mappings().size(), kNumMappings1);
  for (size_t i = 0; i < kNumMappings1; ++i) {
    const auto& mapping = memory_summary.memory_mappings()[i];
    const Snap::MemoryMapping expected = kSnap1.memory_mappings.elements[i];
    EXPECT_EQ(mapping.start_address(), expected.start_address);
    EXPECT_EQ(mapping.num_bytes(), expected.num_bytes);
    EXPECT_EQ(mapping.perms().ToMProtect(), expected.perms);
  }
}

TEST(SnapshotGroup, CanAddSnapshotIntoEmptyGroup) {
  SnapshotGroup snapshot_group(SnapshotGroup::kNoConflictAllowed);
  SnapshotGroup::SnapshotSummary snapshot_summary_1(kSnap1);
  EXPECT_OK(snapshot_group.CanAddSnapshot(snapshot_summary_1));
  snapshot_group.AddSnapshot(snapshot_summary_1);
  EXPECT_EQ(snapshot_group.size(), 1);
}

TEST(SnapshotGroup, PersistentConflict) {
  MappedMemoryMap m;
  m.AddNew(0ULL, ~0ULL, MemoryPerms::AllPlusMapped());
  SnapshotGroup snapshot_group(SnapshotGroup::kNoConflictAllowed, m);
  SnapshotGroup::SnapshotSummary snapshot_summary_1(kSnap1);
  EXPECT_THAT(snapshot_group.CanAddSnapshot(snapshot_summary_1),
              StatusIs(absl::StatusCode::kAlreadyExists,
                       HasSubstr("mapping conflict")));
}

TEST(SnapshotGroup, CanAddSnapshotNoConflict) {
  SnapshotGroup snapshot_group(SnapshotGroup::kNoConflictAllowed);
  SnapshotGroup::SnapshotSummary snapshot_summary_1(kSnap1);
  snapshot_group.AddSnapshot(snapshot_summary_1);
  SnapshotGroup::SnapshotSummary snapshot_summary_2(kSnap2);
  EXPECT_OK(snapshot_group.CanAddSnapshot(snapshot_summary_2));
  snapshot_group.AddSnapshot(snapshot_summary_2);
  EXPECT_EQ(snapshot_group.size(), 2);
}

TEST(SnapshotGroup, CannotAddSnapshotWithReadOnlyConflict) {
  SnapshotGroup snapshot_group(SnapshotGroup::kNoConflictAllowed);
  SnapshotGroup::SnapshotSummary snapshot_summary_1(kSnap1);
  snapshot_group.AddSnapshot(snapshot_summary_1);
  SnapshotGroup::SnapshotSummary snapshot_summary_3(kSnap3);
  EXPECT_THAT(snapshot_group.CanAddSnapshot(snapshot_summary_3),
              StatusIs(absl::StatusCode::kAlreadyExists));
  EXPECT_EQ(snapshot_group.size(), 1);
}

TEST(SnapshotGroup, CanAddSnapshotWriteConflictSamePerms) {
  SnapshotGroup snapshot_group(SnapshotGroup::kAllowWriteConflictsWithSamePerm);
  SnapshotGroup::SnapshotSummary snapshot_summary_1(kSnap1);
  snapshot_group.AddSnapshot(snapshot_summary_1);
  SnapshotGroup::SnapshotSummary snapshot_summary_4(kSnap4);
  EXPECT_OK(snapshot_group.CanAddSnapshot(snapshot_summary_4));
  snapshot_group.AddSnapshot(snapshot_summary_4);
  EXPECT_EQ(snapshot_group.size(), 2);
}

TEST(SnapshotGroup, CannotAddSnapshotWriteConflictDifferentPerms) {
  SnapshotGroup snapshot_group(SnapshotGroup::kAllowWriteConflictsWithSamePerm);
  SnapshotGroup::SnapshotSummary snapshot_summary_1(kSnap1);
  snapshot_group.AddSnapshot(snapshot_summary_1);
  SnapshotGroup::SnapshotSummary snapshot_summary_5(kSnap5);
  EXPECT_THAT(snapshot_group.CanAddSnapshot(snapshot_summary_5),
              StatusIs(absl::StatusCode::kAlreadyExists));
  EXPECT_EQ(snapshot_group.size(), 1);
}

TEST(SnapPartition, OneSnapPerGroup) {
  const SnapshotGroup::SnapshotSummary snapshot_summary_1(kSnap1);
  const SnapshotGroup::SnapshotSummary snapshot_summary_2(kSnap2);
  const SnapshotGroup::SnapshotSummary snapshot_summary_3(kSnap3);
  const SnapshotGroup::SnapshotSummary snapshot_summary_4(kSnap4);
  const SnapshotGroup::SnapshotSummary snapshot_summary_5(kSnap5);
  const SnapshotGroup::SnapshotSummaryList kSnapshotSummaryList{
      snapshot_summary_1, snapshot_summary_2, snapshot_summary_3,
      snapshot_summary_4, snapshot_summary_5};

  // Number of groups == Number of Snaphots. This should trivially
  // put exactly 1 snap per group.
  SnapshotPartition partition(kSnapshotSummaryList.size(),
                              SnapshotGroup::kAllowWriteConflictsWithSamePerm);
  SnapshotGroup::SnapshotSummaryList rejected =
      partition.PartitionSnapshots(kSnapshotSummaryList);
  EXPECT_THAT(rejected, IsEmpty());
  for (const auto& group : partition.snapshot_groups()) {
    EXPECT_EQ(group.size(), 1);
  }
}

// Partition a small example of snapshots with various memory
// mapping conflicts. The example is constructed so that all
// snapshots can be added.
TEST(SnapshotGroup, PartitionSmallExample) {
  const SnapshotGroup::SnapshotSummary snapshot_summary_1(kSnap1);
  const SnapshotGroup::SnapshotSummary snapshot_summary_2(kSnap2);
  const SnapshotGroup::SnapshotSummary snapshot_summary_3(kSnap3);
  const SnapshotGroup::SnapshotSummary snapshot_summary_4(kSnap4);
  const SnapshotGroup::SnapshotSummary snapshot_summary_5(kSnap5);
  const SnapshotGroup::SnapshotSummaryList kSnapshotSummaryList{
      snapshot_summary_1, snapshot_summary_2, snapshot_summary_3,
      snapshot_summary_4, snapshot_summary_5};

  constexpr int kNumGroups = 3;
  SnapshotPartition partition(kNumGroups,
                              SnapshotGroup::kAllowWriteConflictsWithSamePerm);
  SnapshotGroup::SnapshotSummaryList rejected =
      partition.PartitionSnapshots(kSnapshotSummaryList);
  EXPECT_TRUE(rejected.empty());

  absl::flat_hash_set<SnapshotGroup::Id> grouped_ids;
  const size_t group_size_lower_bound =
      kSnapshotSummaryList.size() / kNumGroups;
  const size_t group_size_upper_bound =
      (kSnapshotSummaryList.size() + kNumGroups - 1) / kNumGroups;

  // We expect a roughly even distribution.
  for (const auto& group : partition.snapshot_groups()) {
    EXPECT_GE(group.size(), group_size_lower_bound);
    EXPECT_LE(group.size(), group_size_upper_bound);
    const SnapshotGroup::IdList id_list = group.id_list();
    grouped_ids.insert(id_list.begin(), id_list.end());
  }

  // Check that all snapshots are indeed added.
  EXPECT_EQ(grouped_ids.size(), kSnapshotSummaryList.size());
  for (const auto& summary : kSnapshotSummaryList) {
    EXPECT_THAT(grouped_ids, Contains(summary.id()));
  }
}

// Partition a small example of snapshots with various memory
// mapping conflicts. The example is constructed so that not
// all snapshots can be added as there is too few groups.
TEST(SnapshotGroup, PartitionTooFewGroupsToFit) {
  const SnapshotGroup::SnapshotSummary snapshot_summary_1(kSnap1);
  const SnapshotGroup::SnapshotSummary snapshot_summary_2(kSnap2);
  const SnapshotGroup::SnapshotSummary snapshot_summary_3(kSnap3);
  const SnapshotGroup::SnapshotSummary snapshot_summary_4(kSnap4);
  const SnapshotGroup::SnapshotSummary snapshot_summary_5(kSnap5);
  const SnapshotGroup::SnapshotSummaryList kSnapshotSummaryList{
      snapshot_summary_1, snapshot_summary_2, snapshot_summary_3,
      snapshot_summary_4, snapshot_summary_5};

  // We need 3 groups at least.
  constexpr int kNumGroups = 2;
  SnapshotPartition partition(kNumGroups,
                              SnapshotGroup::kAllowWriteConflictsWithSamePerm);
  SnapshotGroup::SnapshotSummaryList rejected =
      partition.PartitionSnapshots(kSnapshotSummaryList);
  // There should be rejected snapshots.
  EXPECT_THAT(rejected, Not(IsEmpty()));
}

}  // namespace
}  // namespace silifuzz
