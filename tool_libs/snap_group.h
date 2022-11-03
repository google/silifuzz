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

#ifndef THIRD_PARTY_SILIFUZZ_TOOL_LIBS_SNAP_GROUP_H_
#define THIRD_PARTY_SILIFUZZ_TOOL_LIBS_SNAP_GROUP_H_

#include <cstddef>
#include <vector>

#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "./common/mapped_memory_map.h"
#include "./common/snapshot.h"
#include "./snap/snap.h"
#include "./snap/snap_util.h"

namespace silifuzz {

// SnapshotGroup class facilitates grouping of snapshots to avoid memory mapping
// conflicts so that the snapshots can be put into the same runner. If two snaps
// have any conflicting mapping, they cannot be placed into the same runner
// except when the conflict is for multiple writable mappings of the exactly the
// same permission. The exception is allowed since runner currently runs snaps
// sequentially, so any writable mapping is initialized before a snapshot is
// executed.
//
// Example usage, greedily grouping as many snapshots as possible:
//
// SnapshotGroup group;
// for (const SnapshotSummary& summary : snapshot_summaries) {
//    if (group.CanAddSnapshot(summary)) {
//      group.AddSnapshot(summary);
//    }
// }
//
// This class is thread-compatible.
class SnapshotGroup {
 public:
  // Different policies to resolve mapping conflicts. These controls whether
  // a Snapshot can be added to a group or not if it contains any mapping
  // conflicts with the existing ones in the group.
  enum ConflictResolution {
    // No mapping conflict is allowed.
    kNoConflictAllowed = 0,

    // A mapping conflict is allowed if both mappings have identical
    // memory permission that allows write.
    kAllowWriteConflictsWithSamePerm = 1,
  };

  // We assume Snaps are uniquely identified by their IDs.
  using Id = Snapshot::Id;

  using IdList = std::vector<Snapshot::Id>;

  // This class contains all necessary information about a Snap that is required
  // for grouping. This is used to reduce memory footprint when a big corpus is
  // read into memory for grouping.
  //
  // Note: at some point, we may include other summary information than
  // mapping information. For example, we might want to have some measure of
  // snapshot size here to let us create equally-sized groups.
  class SnapshotSummary {
   public:
    using MemoryMappingList = Snapshot::MemoryMappingList;

    explicit SnapshotSummary(const Snapshot& snapshot);
    ~SnapshotSummary() = default;

    // Copyable and movable by default.

    const Id& id() const { return id_; }
    const MemoryMappingList& memory_mappings() const {
      return memory_mappings_;
    }

    // Helper struct to sort SnapshotSummaries.
    struct LessThan {
      bool operator()(const SnapshotGroup::SnapshotSummary& lhs,
                      const SnapshotGroup::SnapshotSummary& rhs) const {
        if (lhs.sort_key_ != rhs.sort_key_) {
          return lhs.sort_key_ < rhs.sort_key_;
        }
        return lhs.id() < rhs.id();
      }
    };

   private:
    friend struct LessThan;
    // Id of the Snap of which memory mappings are described by this.
    Id id_;

    // Memory mappings of the Snap.
    MemoryMappingList memory_mappings_;

    // Sort key used by LessThan to order snapshots.
    int sort_key_;
  };

  using SnapshotSummaryList = std::vector<SnapshotSummary>;

  // Constructs a new SnapshotGroup with the given conflict resolution policy
  // and mapped memory map. The latter can be used to create "persistent"
  // mappings that are not owned by any Snapshots in the group but exist
  // in the environment (e.g. nullptr is never mappable on real hardware).
  explicit SnapshotGroup(ConflictResolution conflict_resolution,
                         const MappedMemoryMap& mapped_memory_map = {})
      : conflict_resolution_(conflict_resolution),
        mapped_memory_map_(mapped_memory_map.Copy()) {}
  ~SnapshotGroup() = default;

  // Movable, but not copyable (can be large and expensive to copy by accident).
  SnapshotGroup(const SnapshotGroup&) = delete;
  SnapshotGroup(SnapshotGroup&&) = default;
  SnapshotGroup& operator=(const SnapshotGroup&) = delete;
  SnapshotGroup& operator=(SnapshotGroup&&) = default;

  // Returns OkStatus() iff snapshot described by 'summary' can be added
  // into this group. This is determined based on conflict resolution policy
  // of this group. See ConflictResolution enum above for details.
  absl::Status CanAddSnapshot(const SnapshotSummary& summary);

  // Adds snap described by 'summary' into this group.
  // REQUIRES: CanAddSnapshot(summary) is ok.
  void AddSnapshot(const SnapshotSummary& summary);

  // Returns a list of all snapshot IDs in this group. This creates a new list
  // and it takes O(n) time.
  IdList id_list() const { return IdList(id_set_.begin(), id_set_.end()); }

  // Returns number of Snaps in this group.
  size_t size() const { return id_set_.size(); }

 private:
  // Conflict resolution.
  ConflictResolution conflict_resolution_;

  // IDs of Snaps in this group.
  absl::flat_hash_set<Id> id_set_;

  // Union of memory mappings used by Snaps in this group.
  // All mappings in mapped_memory_map_ have permission kMapped set.
  MappedMemoryMap mapped_memory_map_;
};

// In some usage, we want to break a set of snapshots into a number of
// non-overlapping subsets. This class is designed to partition snapshots
// into rougly equal sized groups, each of which contains only non-conflicting
// snapshots.
//
// This class is thread-compatible.
class SnapshotPartition {
 public:
  using SnapshotSummary = SnapshotGroup::SnapshotSummary;
  using SnapshotSummaryList = SnapshotGroup::SnapshotSummaryList;

  // Construct a SnapshotPartition that contains 'num_groups' of disjoint
  // groups, i.e. any snapshot can only appear in at most one of the groups.
  // The `conflict_mapped_memory` contains pre-existing mappings that are not
  // owned by any Snapshot but still must be excluded (e.g. the exit
  // trampoline mapping).
  SnapshotPartition(size_t num_groups,
                    SnapshotGroup::ConflictResolution conflict_resolution,
                    const MappedMemoryMap& conflict_mapped_memory = {});

  ~SnapshotPartition() = default;

  // Movable, but not copyable (can be large and expensive to copy by accident).
  SnapshotPartition(const SnapshotPartition&) = delete;
  SnapshotPartition(SnapshotPartition&&) = default;
  SnapshotPartition& operator=(const SnapshotPartition&) = delete;
  SnapshotPartition& operator=(SnapshotPartition&&) = default;

  // Returns the groups representing this partitioning.
  const std::vector<SnapshotGroup>& snapshot_groups() const {
    return snapshot_groups_;
  }

  // Deterministically partitions snaphots described by 'summaries' into groups
  // of this so that the groups have approximately same sizes. Returns
  // unadded snapshots that are rejected due to mapping conflicts. Note that the
  // groups may be non-empty before call.
  //
  // There is no guranteed that we can adds all snapshots. A caller may need to
  // call this multiple times until all snapshots are inserted. The caller may
  // also shuffle the input to make it less likely conflicting snapshots to be
  // considered for addition into the same group.
  //
  // Example usage:
  //
  // SnapshotPartition partition(num_groups);
  // SnapshotSummaryList ungrouped = ...;
  // for (int i = 0; i < kMaxIterations && !ungrouped.empty(); ++i) {
  //    std::shuffle(ungrouped.begin(), ungrouped.end(), random_gen);
  //    ungrouped = parition.PartitionSnapshots(ungrouped);
  // }
  //
  SnapshotSummaryList PartitionSnapshots(const SnapshotSummaryList& summaries);

 private:
  std::vector<SnapshotGroup> snapshot_groups_;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_TOOL_LIBS_SNAP_GROUP_H_
