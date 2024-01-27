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
#include "./tool_libs/corpus_partitioner_lib.h"

#include <stdint.h>

#include <algorithm>
#include <cstddef>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "./common/memory_mapping.h"
#include "./common/memory_perms.h"
#include "./common/snapshot.h"
#include "./tool_libs/snap_group.h"
#include "./util/checks.h"

namespace silifuzz {
namespace {

using ::testing::UnorderedElementsAreArray;

SnapshotGroup::SnapshotSummaryList GenTestSnapshotSummaryList(
    size_t num_snapshots) {
  SnapshotGroup::SnapshotSummaryList result;
  // This just creates a list of disjoint SnapshotSummaries. The logic for
  // dealing with overlapping SnapshotSummaries is tested in ShortshotGroup's
  // tests.
  for (int i = 0; i < num_snapshots; ++i) {
    // Create an incomplete snapshot just enough to get us a SnapshotSummary.
    std::string id = absl::StrCat("snapshot_", i);
    Snapshot snapshot(Snapshot::CurrentArchitecture(), id);
    constexpr Snapshot::Address kBasePageNumber = 0x2000;
    const Snapshot::Address mapping_start =
        (kBasePageNumber + i) * snapshot.page_size();
    MemoryMapping mapping = MemoryMapping::MakeSized(
        mapping_start, snapshot.page_size(), MemoryPerms::RWX());
    CHECK_STATUS(snapshot.can_add_memory_mapping(mapping));
    result.push_back(SnapshotGroup::SnapshotSummary(snapshot));
  }
  return result;
}

TEST(CorpusPartitionerLib, SimpleTest) {
  constexpr size_t kNumSnaps = 10;
  constexpr int32_t kNumGroups = 10;
  constexpr int32_t kNumIterations = 1;
  SnapshotGroup::SnapshotSummaryList list =
      GenTestSnapshotSummaryList(kNumSnaps);
  SnapshotPartition partition =
      PartitionCorpus(kNumGroups, kNumIterations, list);
  const auto& groups = partition.snapshot_groups();
  EXPECT_EQ(groups.size(), kNumGroups);
  for (const auto& group : groups) {
    EXPECT_EQ(group.size(), 1);
  }
}

TEST(CorpusPartitionerLib, IsDeterministic) {
  constexpr size_t kNumSnaps = 100;
  constexpr int32_t kNumGroups = 10;
  constexpr int32_t kNumIterations = 10;
  SnapshotGroup::SnapshotSummaryList list1 =
      GenTestSnapshotSummaryList(kNumSnaps);
  SnapshotGroup::SnapshotSummaryList list2 = list1;
  std::random_shuffle(list2.begin(), list2.end());

  SnapshotPartition partition1 =
      PartitionCorpus(kNumGroups, kNumIterations, list1);
  SnapshotPartition partition2 =
      PartitionCorpus(kNumGroups, kNumIterations, list2);
  const auto& groups1 = partition1.snapshot_groups();
  const auto& groups2 = partition2.snapshot_groups();
  EXPECT_EQ(groups1.size(), groups2.size());
  size_t min_size = std::min(groups1.size(), groups2.size());
  // Grouping is deterministic but ordering of Snapshots within each group
  // is not.
  for (size_t i = 0; i < min_size; ++i) {
    EXPECT_THAT(groups1[i].id_list(),
                UnorderedElementsAreArray(groups2[i].id_list()));
  }
}

}  // namespace

}  // namespace silifuzz
