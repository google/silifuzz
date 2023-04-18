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

#ifndef THIRD_PARTY_SILIFUZZ_COMMON_SNAPSHOT_PROTO_H_
#define THIRD_PARTY_SILIFUZZ_COMMON_SNAPSHOT_PROTO_H_

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "./common/snapshot.h"
#include "./common/snapshot_types.h"
#include "./proto/snapshot.pb.h"

namespace silifuzz {

// A collection of utilities to convert between the Snapshot class
// and its proto representation, proto::Snapshot.
class SnapshotProto : private SnapshotTypeNames {
 public:
  // Attempts to build a Snapshot from proto.
  // Returns an error status if unsuccessful.
  // PROVIDES: Snapshot::IsCompleteSomeState() for the returned snapshot.
  static absl::StatusOr<Snapshot> FromProto(const proto::Snapshot& proto);

  // Returns true iff the given snapshot proto is valid
  // (a Snapshot can be made from it with FromProto()).
  // A convenience helper: is as expensive as FromProto().
  static absl::Status IsValid(const proto::Snapshot& proto);

  // Dumps Snapshot into proto representation.
  // REQUIRES: snap.IsCompleteSomeState()
  static void ToProto(const Snapshot& snap, proto::Snapshot* proto);

  // Like the above but for EndState submessage. Used by PlayerResultProto.
  static absl::StatusOr<EndState> FromProto(const proto::EndState& proto);
  static void ToProto(const EndState& snap, proto::EndState* proto);

  // FromProto() overloads for snapshot submessage types.
  static absl::StatusOr<MemoryMapping> FromProto(
      const proto::MemoryMapping& proto);
  static absl::StatusOr<MemoryBytes> FromProto(const proto::MemoryBytes& proto);
  static absl::StatusOr<RegisterState> FromProto(
      const proto::RegisterState& proto);
  static absl::StatusOr<Endpoint> FromProto(const proto::Endpoint& proto);
  static absl::StatusOr<Metadata> FromProto(
      const proto::SnapshotMetadata& proto);

  // ToProto() overloads for snapshot submessage types.
  static void ToProto(const MemoryMapping& snap, proto::MemoryMapping* proto);
  static void ToProto(const MemoryBytes& snap, proto::MemoryBytes* proto);
  static void ToProto(const RegisterState& snap, proto::RegisterState* proto);
  static void ToProto(const Endpoint& snap, proto::Endpoint* proto);
  static void ToProto(const Metadata& metadata, proto::SnapshotMetadata* proto);
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_COMMON_SNAPSHOT_PROTO_H_
