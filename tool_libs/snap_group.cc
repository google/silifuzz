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

#include <sys/types.h>

#include <cstddef>
#include <vector>

#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "./common/mapped_memory_map.h"
#include "./common/memory_perms.h"
#include "./common/snapshot.h"
#include "./util/checks.h"

namespace silifuzz {

absl::Status SnapshotGroup::CanAddSnapshot(
    const SnapshotSummary& snapshot_summary) {
  // Cannot add a Snap that is already in group.
  if (id_set_.contains(snapshot_summary.id())) {
    return absl::AlreadyExistsError("Id already exists");
  }

  // Check mappings of snap for conflicts with existing mappings.
  for (const auto& mapping : snapshot_summary.memory_mappings()) {
    // Writable mapping can overlap with mappings having exactly the same
    // permissions if conflict resolution permits.
    if (conflict_resolution_ == kAllowWriteConflictsWithSamePerm &&
        mapping.perms().Has(MemoryPerms::kWritable)) {
      MemoryPerms mapped_perms = mapping.perms().Plus(MemoryPerms::kMapped);
      bool can_add_writable_mapping = true;
      auto check_existing_perms = [&can_add_writable_mapping, mapped_perms](
                                      Snapshot::Address start,
                                      Snapshot::Address limit,
                                      MemoryPerms perms) {
        if (perms != mapped_perms) {
          can_add_writable_mapping = false;
        }
      };
      mapped_memory_map_.Iterate(check_existing_perms, mapping.start_address(),
                                 mapping.limit_address());

      // If the range contains existing mappings, the existing mappings must
      // all have the same permission as the new mapping.
      if (!can_add_writable_mapping) {
        return absl::AlreadyExistsError("writable mapping conflict");
      }
    } else {
      if (mapped_memory_map_.Overlaps(mapping.start_address(),
                                      mapping.limit_address())) {
        return absl::AlreadyExistsError("mapping conflict");
      }
    }
  }
  return absl::OkStatus();
}

void SnapshotGroup::AddSnapshot(const SnapshotSummary& snapshot_summary) {
  DCHECK(CanAddSnapshot(snapshot_summary).ok());

  for (const auto& mapping : snapshot_summary.memory_mappings()) {
    mapped_memory_map_.Add(mapping.start_address(), mapping.limit_address(),
                           mapping.perms().Plus(MemoryPerms::kMapped));
  }
  id_set_.insert(snapshot_summary.id());
}

// ----------------------------------------------------------------------- //

SnapshotPartition::SnapshotPartition(
    size_t num_groups, SnapshotGroup::ConflictResolution conflict_resolution,
    const MappedMemoryMap& conflict_mapped_memory) {
  for (size_t i = 0; i < num_groups; ++i) {
    snapshot_groups_.push_back(
        SnapshotGroup(conflict_resolution, conflict_mapped_memory));
  }
}

SnapshotPartition::SnapshotSummaryList SnapshotPartition::PartitionSnapshots(
    const SnapshotSummaryList& snapshot_summaries) {
  // Compute number of snapshots if all snapshot_summaries can be added
  size_t num_snapshots = snapshot_summaries.size();
  for (const auto& group : snapshot_groups_) {
    num_snapshots += group.size();
  }

  // Try to make groups about the same size.
  const size_t group_size = num_snapshots / snapshot_groups_.size();
  const size_t remainder = num_snapshots % snapshot_groups_.size();
  std::vector<size_t> target_group_size(snapshot_groups_.size());
  for (size_t i = 0; i < snapshot_groups_.size(); ++i) {
    target_group_size[i] = group_size + (i < remainder ? 1 : 0);
  }

  // This loop below can be parallelized by using a thread to handle each group
  // Each group can keep its  own rejected snap list and all individual reject
  // snap lists are merged at the end an iteration into a single list.
  SnapshotPartition::SnapshotSummaryList rejected;
  size_t offset = 0;
  for (size_t i = 0; i < snapshot_groups_.size(); ++i) {
    SnapshotGroup& group = snapshot_groups_[i];
    const ssize_t chunk_size = target_group_size[i] - group.size();
    if (chunk_size == 0) {
      continue;
    }

    DCHECK_GT(chunk_size, 0);
    DCHECK_LE(offset + chunk_size, snapshot_summaries.size());
    for (size_t j = offset; j < offset + chunk_size; ++j) {
      const SnapshotSummary& summary = snapshot_summaries[j];
      if (group.CanAddSnapshot(summary).ok()) {
        group.AddSnapshot(summary);
      } else {
        rejected.push_back(summary);
      }
    }
    offset += chunk_size;
  }
  return rejected;
}

}  // namespace silifuzz
