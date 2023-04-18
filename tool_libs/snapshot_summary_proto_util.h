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

#ifndef THIRD_PARTY_SILIFUZZ_TOOL_LIBS_SNAPSHOT_SUMMARY_PROTO_UTIL_H_
#define THIRD_PARTY_SILIFUZZ_TOOL_LIBS_SNAPSHOT_SUMMARY_PROTO_UTIL_H_

#include "absl/status/statusor.h"
#include "./proto/snapshot.pb.h"
#include "./tool_libs/snap_group.h"

namespace silifuzz {

class SnapshotSummaryProto final {
 public:
  static absl::StatusOr<SnapshotGroup::SnapshotSummary> FromProto(
      const proto::SnapshotSummary& proto);
  static void ToProto(const SnapshotGroup::SnapshotSummary& summary,
                      proto::SnapshotSummary* proto);
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_TOOL_LIBS_SNAPSHOT_SUMMARY_PROTO_UTIL_H_
