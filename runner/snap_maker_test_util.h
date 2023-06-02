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
//
// Utilities for snap maker test.

#ifndef THIRD_PARTY_SILIFUZZ_RUNNER_SNAP_MAKER_TEST_UTIL_H_
#define THIRD_PARTY_SILIFUZZ_RUNNER_SNAP_MAKER_TEST_UTIL_H_

#include "absl/status/statusor.h"
#include "./common/snapshot.h"
#include "./player/trace_options.h"
#include "./runner/snap_maker.h"

namespace silifuzz {

// Default snap maker options for snap maker tests.
SnapMaker::Options DefaultSnapMakerOptionsForTest();

// Applies Make(), Record() and Verify() to the snapshot and returns either
// the fixed Snapshot or an error.
absl::StatusOr<Snapshot> FixSnapshotInTest(
    const Snapshot& snapshot,
    const SnapMaker::Options& options = DefaultSnapMakerOptionsForTest(),
    const TraceOptions& trace_options = TraceOptions::Default());

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_RUNNER_SNAP_MAKER_TEST_UTIL_H_
