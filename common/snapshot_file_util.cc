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

#include "./common/snapshot_file_util.h"

#include "absl/status/statusor.h"
#include "./common/snapshot_proto.h"
#include "./util/checks.h"
#include "./util/proto_util.h"

namespace silifuzz {

absl::Status WriteSnapshotToFile(const Snapshot& snapshot,
                                 absl::string_view filename) {
  proto::Snapshot proto;
  SnapshotProto::ToProto(snapshot, &proto);
  return WriteToFile(proto, filename);
}

void WriteSnapshotToFileOrDie(const Snapshot& snapshot,
                              absl::string_view filename) {
  auto s = WriteSnapshotToFile(snapshot, filename);
  CHECK_STATUS(s);
}

absl::StatusOr<Snapshot> ReadSnapshotFromFile(absl::string_view filename) {
  proto::Snapshot snap_proto;
  auto s = ReadFromFile(filename, &snap_proto);
  RETURN_IF_NOT_OK(s);

  auto snapshot_or = SnapshotProto::FromProto(snap_proto);
  RETURN_IF_NOT_OK_PLUS(snapshot_or.status(),
                        "Could not parse Snapshot from proto: ");
  return snapshot_or;
}

Snapshot ReadSnapshotFromFileOrDie(absl::string_view filename) {
  auto snapshot_or = ReadSnapshotFromFile(filename);
  CHECK_STATUS(snapshot_or.status());
  return std::move(snapshot_or).value();
}

}  // namespace silifuzz
