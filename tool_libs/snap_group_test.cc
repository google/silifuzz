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

const std::vector<Snapshot>& TestSnapshots() {
  static std::vector<Snapshot>* snapshots = [] {
    Snapshot s1(Snapshot::Architecture::kX86_64, "snap1");
    s1.add_memory_mapping(
        MemoryMapping::MakeSized(0x1234000ULL, 0x4000, MemoryPerms::XR()));
    s1.add_memory_mapping(
        MemoryMapping::MakeSized(0x5678000ULL, 0x1000, MemoryPerms::RW()));

    Snapshot::EndState es1(Snapshot::Endpoint(0x1234000ULL));
    es1.add_platform(PlatformId::kIntelHaswell);
    CHECK_STATUS(s1.can_add_expected_end_state(es1));
    s1.add_expected_end_state(es1);

    // No conflict with kSnap1.
    Snapshot s2(Snapshot::Architecture::kX86_64, "snap2");
    s2.add_memory_mapping(
        MemoryMapping::MakeSized(0x3456000ULL, 0x4000, MemoryPerms::XR()));
    s2.add_memory_mapping(
        MemoryMapping::MakeSized(0x789a000ULL, 0x1000, MemoryPerms::RW()));
    Snapshot::EndState es2(Snapshot::Endpoint(0x3456000ULL));
    es2.add_platform(PlatformId::kIntelHaswell);
    es2.add_platform(PlatformId::kIntelBroadwell);
    CHECK_STATUS(s2.can_add_expected_end_state(es2));
    s2.add_expected_end_state(es2);

    // Read-only mapping conflict with kSnap1
    Snapshot s3(Snapshot::Architecture::kX86_64, "snap3");
    s3.add_memory_mapping(
        MemoryMapping::MakeSized(0x1234000ULL, 0x4000, MemoryPerms::XR()));
    s3.add_memory_mapping(
        MemoryMapping::MakeSized(0x6789000ULL, 0x2000, MemoryPerms::RW()));

    // Writable mapping conflict with kSnap1, same permissions.
    Snapshot s4(Snapshot::Architecture::kX86_64, "snap4");
    s4.add_memory_mapping(
        MemoryMapping::MakeSized(0x2345000ULL, 0x4000, MemoryPerms::XR()));
    s4.add_memory_mapping(
        MemoryMapping::MakeSized(0x5678000ULL, 0x2000, MemoryPerms::RW()));

    // Writable mapping conflict with kSnap1, different permissions.
    // Read-only conflict with kSnap2.
    Snapshot s5(Snapshot::Architecture::kX86_64, "snap5");
    s5.add_memory_mapping(
        MemoryMapping::MakeSized(0x3456000ULL, 0x4000, MemoryPerms::XR()));
    s5.add_memory_mapping(
        MemoryMapping::MakeSized(0x5678000ULL, 0x2000, MemoryPerms::RWX()));

    std::vector<Snapshot>* rv = new std::vector<Snapshot>();
    rv->push_back(std::move(s1));
    rv->push_back(std::move(s2));
    rv->push_back(std::move(s3));
    rv->push_back(std::move(s4));
    rv->push_back(std::move(s5));
    return rv;
  }();
  return *snapshots;
}

TEST(SnapshotSummary, ConstructFromSnapshot) {
  Snapshot snapshot = CreateTestSnapshot(TestSnapshot::kEndsAsExpected);
  SnapshotGroup::SnapshotSummary memory_summary(snapshot);
  EXPECT_EQ(memory_summary.id(), snapshot.id());
  EXPECT_EQ(memory_summary.memory_mappings(), snapshot.memory_mappings());
}

TEST(SnapshotGroup, CanAddSnapshotIntoEmptyGroup) {
  SnapshotGroup snapshot_group(SnapshotGroup::kNoConflictAllowed);
  SnapshotGroup::SnapshotSummary snapshot_summary_1(TestSnapshots()[0]);
  EXPECT_OK(snapshot_group.CanAddSnapshot(snapshot_summary_1));
  snapshot_group.AddSnapshot(snapshot_summary_1);
  EXPECT_EQ(snapshot_group.size(), 1);
}

TEST(SnapshotGroup, PersistentConflict) {
  MappedMemoryMap m;
  m.AddNew(0ULL, ~0ULL, MemoryPerms::AllPlusMapped());
  SnapshotGroup snapshot_group(SnapshotGroup::kNoConflictAllowed, m);
  SnapshotGroup::SnapshotSummary snapshot_summary_1(TestSnapshots()[0]);
  EXPECT_THAT(snapshot_group.CanAddSnapshot(snapshot_summary_1),
              StatusIs(absl::StatusCode::kAlreadyExists,
                       HasSubstr("mapping conflict")));
}

TEST(SnapshotGroup, CanAddSnapshotNoConflict) {
  SnapshotGroup snapshot_group(SnapshotGroup::kNoConflictAllowed);
  SnapshotGroup::SnapshotSummary snapshot_summary_1(TestSnapshots()[0]);
  snapshot_group.AddSnapshot(snapshot_summary_1);
  SnapshotGroup::SnapshotSummary snapshot_summary_2(TestSnapshots()[1]);
  EXPECT_OK(snapshot_group.CanAddSnapshot(snapshot_summary_2));
  snapshot_group.AddSnapshot(snapshot_summary_2);
  EXPECT_EQ(snapshot_group.size(), 2);
}

TEST(SnapshotGroup, CannotAddSnapshotWithReadOnlyConflict) {
  SnapshotGroup snapshot_group(SnapshotGroup::kNoConflictAllowed);
  SnapshotGroup::SnapshotSummary snapshot_summary_1(TestSnapshots()[0]);
  snapshot_group.AddSnapshot(snapshot_summary_1);
  SnapshotGroup::SnapshotSummary snapshot_summary_3(TestSnapshots()[2]);
  EXPECT_THAT(snapshot_group.CanAddSnapshot(snapshot_summary_3),
              StatusIs(absl::StatusCode::kAlreadyExists));
  EXPECT_EQ(snapshot_group.size(), 1);
}

TEST(SnapshotGroup, CanAddSnapshotWriteConflictSamePerms) {
  SnapshotGroup snapshot_group(SnapshotGroup::kAllowWriteConflictsWithSamePerm);
  SnapshotGroup::SnapshotSummary snapshot_summary_1(TestSnapshots()[0]);
  snapshot_group.AddSnapshot(snapshot_summary_1);
  SnapshotGroup::SnapshotSummary snapshot_summary_4(TestSnapshots()[3]);
  EXPECT_OK(snapshot_group.CanAddSnapshot(snapshot_summary_4));
  snapshot_group.AddSnapshot(snapshot_summary_4);
  EXPECT_EQ(snapshot_group.size(), 2);
}

TEST(SnapshotGroup, CannotAddSnapshotWriteConflictDifferentPerms) {
  SnapshotGroup snapshot_group(SnapshotGroup::kAllowWriteConflictsWithSamePerm);
  SnapshotGroup::SnapshotSummary snapshot_summary_1(TestSnapshots()[0]);
  snapshot_group.AddSnapshot(snapshot_summary_1);
  SnapshotGroup::SnapshotSummary snapshot_summary_5(TestSnapshots()[4]);
  EXPECT_THAT(snapshot_group.CanAddSnapshot(snapshot_summary_5),
              StatusIs(absl::StatusCode::kAlreadyExists));
  EXPECT_EQ(snapshot_group.size(), 1);
}

TEST(SnapPartition, OneSnapPerGroup) {
  SnapshotGroup::SnapshotSummaryList kSnapshotSummaryList;
  for (const auto& s : TestSnapshots()) {
    kSnapshotSummaryList.emplace_back(s);
  }

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
  SnapshotGroup::SnapshotSummaryList kSnapshotSummaryList;
  for (const auto& s : TestSnapshots()) {
    kSnapshotSummaryList.emplace_back(s);
  }

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
  SnapshotGroup::SnapshotSummaryList kSnapshotSummaryList;
  for (const auto& s : TestSnapshots()) {
    kSnapshotSummaryList.emplace_back(s);
  }

  // We need 3 groups at least.
  constexpr int kNumGroups = 2;
  SnapshotPartition partition(kNumGroups,
                              SnapshotGroup::kAllowWriteConflictsWithSamePerm);
  SnapshotGroup::SnapshotSummaryList rejected =
      partition.PartitionSnapshots(kSnapshotSummaryList);
  // There should be rejected snapshots.
  EXPECT_THAT(rejected, Not(IsEmpty()));
}

TEST(SnapshotGroup, LessThan) {
  SnapshotGroup::SnapshotSummary snapshot_summary_1(TestSnapshots()[0]);
  SnapshotGroup::SnapshotSummary snapshot_summary_2(TestSnapshots()[1]);

  SnapshotGroup::SnapshotSummary::LessThan lt;

  // Test that sort_key (number of end states and platforms) takes precedence
  // over the ID when sorting according to LessThan.
  EXPECT_LT(snapshot_summary_1.id(), snapshot_summary_2.id());
  EXPECT_TRUE(lt(snapshot_summary_2, snapshot_summary_1));
}

}  // namespace
}  // namespace silifuzz
