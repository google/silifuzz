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

#ifndef THIRD_PARTY_SILIFUZZ_SNAP_TESTING_SNAP_TEST_SNAPSHOTS_H_
#define THIRD_PARTY_SILIFUZZ_SNAP_TESTING_SNAP_TEST_SNAPSHOTS_H_
#include "./common/snapshot.h"
#include "./common/snapshot_test_enum.h"
#include "./snap/testing/snap_test_types.h"

namespace silifuzz {

// Returns a silifuzz::Snapshot of the given Snap generator test type.
template <typename Arch = Host>
Snapshot MakeSnapGeneratorTestSnapshot(SnapGeneratorTestType type);

// Returns a silifuzz::Snapshot of the given Snap runner test type.
template <typename Arch = Host>
Snapshot MakeSnapRunnerTestSnapshot(TestSnapshot type);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_SNAP_TESTING_SNAP_TEST_SNAPSHOTS_H_
