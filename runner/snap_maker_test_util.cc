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

#include "./runner/snap_maker_test_util.h"

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "./runner/runner_provider.h"
#include "./runner/snap_maker.h"

namespace silifuzz {

SnapMaker::Options DefaultSnapMakerOptionsForTest() {
  SnapMaker::Options opts;
  opts.runner_path = RunnerLocation();
  return opts;
}

absl::StatusOr<Snapshot> FixSnapshotInTest(const Snapshot& snapshot,
                                           const SnapMaker::Options& options) {
  SnapMaker snap_maker(options);
  auto made_snapshot_or = snap_maker.Make(snapshot);
  RETURN_IF_NOT_OK(made_snapshot_or.status());
  auto recorded_snap_or = snap_maker.RecordEndState(made_snapshot_or.value());
  RETURN_IF_NOT_OK(recorded_snap_or.status());
  auto verify_status = snap_maker.Verify(recorded_snap_or.value());
  if (!verify_status.ok()) {
    return verify_status;
  }
  return recorded_snap_or;
}

}  // namespace silifuzz
