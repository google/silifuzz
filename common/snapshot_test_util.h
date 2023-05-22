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

#ifndef THIRD_PARTY_SILIFUZZ_COMMON_SNAPSHOT_TEST_UTIL_H_
#define THIRD_PARTY_SILIFUZZ_COMMON_SNAPSHOT_TEST_UTIL_H_

#include "./common/snapshot.h"
#include "./common/snapshot_test_enum.h"
#include "./proto/snapshot.pb.h"

namespace silifuzz {

// Options for Create() and CreateProto() below.
class CreateTestSnapshotOptions {
 public:
  static CreateTestSnapshotOptions Default() {
    return CreateTestSnapshotOptions();
  }

  // If set, the returned snapshot will always have a normal state. This
  // is only useful for Snap/Runner testing.
  bool force_normal_state = false;

  // Addresses from which to read/write/execute. The values can be accessed
  // by the snapshot as 0(%rbp), 8(%rbp) and 16(%rbp).
  // Used by some snapshots only.
  Snapshot::Address read_address = 0x300;
  Snapshot::Address write_address = 0x300;
  Snapshot::Address exec_address = 0x300;
};

// Not every test snapshot exists for every architecture.
// Check if this test snapshot exists for this architecture.
template <typename Arch>
bool TestSnapshotExists(TestSnapshot type);

// Creates a minimal snapshot for testing on the current architecture.
template <typename Arch>
Snapshot CreateTestSnapshot(
    TestSnapshot type,
    CreateTestSnapshotOptions options = CreateTestSnapshotOptions::Default());

// Like Create() but returns the snapshot as a proto.
template <typename Arch>
proto::Snapshot CreateTestSnapshotProto(
    TestSnapshot type,
    CreateTestSnapshotOptions options = CreateTestSnapshotOptions::Default());

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_COMMON_SNAPSHOT_TEST_UTIL_H_
