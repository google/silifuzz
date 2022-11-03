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

#include <algorithm>

#include "absl/algorithm/container.h"
#include "./tool_libs/snap_group.h"
#include "./util/checks.h"

namespace silifuzz {

SnapshotPartition PartitionCorpus(
    int32_t num_groups, int32_t num_iterations,
    SnapshotGroup::SnapshotSummaryList& ungrouped) {
  // Sort summaries to make output deterministics.
  absl::c_sort(ungrouped, SnapshotGroup::SnapshotSummary::LessThan());

  VLOG_INFO(1, "Partitioning ", ungrouped.size(), " snapshots into ",
            num_groups);
  SnapshotPartition partition(num_groups,
                              SnapshotGroup::kAllowWriteConflictsWithSamePerm);
  for (int32_t i = 0; i < num_iterations && !ungrouped.empty(); ++i) {
    ungrouped = partition.PartitionSnapshots(ungrouped);
  }

  if (!ungrouped.empty()) {
    LOG_INFO(ungrouped.size(), " snapshots are still ungrouped after ",
             num_iterations, " iterations.");
  }
  return partition;
}

}  // namespace silifuzz

