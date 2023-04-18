// Copyright 2023 The SiliFuzz Authors.
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

#include "./tool_libs/snapshot_summary_proto_util.h"

#include "absl/status/statusor.h"
#include "./common/snapshot_proto.h"
#include "./proto/snapshot.pb.h"
#include "./tool_libs/snap_group.h"
#include "./util/checks.h"

namespace silifuzz {

absl::StatusOr<SnapshotGroup::SnapshotSummary> SnapshotSummaryProto::FromProto(
    const proto::SnapshotSummary& proto) {
  SnapshotGroup::SnapshotSummary::MemoryMappingList memory_mappings;
  for (const proto::MemoryMapping& mp : proto.memory_mappings()) {
    ASSIGN_OR_RETURN_IF_NOT_OK(auto m, SnapshotProto::FromProto(mp));
    memory_mappings.emplace_back(m);
  }
  return SnapshotGroup::SnapshotSummary(proto.id(), memory_mappings,
                                        proto.sort_key());
}

void SnapshotSummaryProto::ToProto(
    const SnapshotGroup::SnapshotSummary& summary,
    proto::SnapshotSummary* summary_proto) {
  summary_proto->set_id(summary.id());
  summary_proto->set_sort_key(summary.sort_key());
  for (const MemoryMapping& m : summary.memory_mappings()) {
    SnapshotProto::ToProto(m, summary_proto->add_memory_mappings());
  }
}

}  // namespace silifuzz
