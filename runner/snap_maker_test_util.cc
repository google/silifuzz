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

#include "absl/status/statusor.h"
#include "./common/snapshot.h"
#include "./runner/runner_provider.h"
#include "./runner/snap_maker.h"

namespace silifuzz {

SnapMaker::Options DefaultSnapMakerOptionsForTest() {
  SnapMaker::Options opts;
  opts.runner_path = RunnerLocation();
  return opts;
}

absl::StatusOr<Snapshot> FixSnapshotInTest(const Snapshot& snapshot,
                                           const SnapMaker::Options& options,
                                           const TraceOptions& trace_options) {
  SnapMaker snap_maker(options);
  ASSIGN_OR_RETURN_IF_NOT_OK(Snapshot made_snapshot, snap_maker.Make(snapshot));
  ASSIGN_OR_RETURN_IF_NOT_OK(Snapshot recorded_snap,
                             snap_maker.RecordEndState(made_snapshot));
  RETURN_IF_NOT_OK(snap_maker.VerifyPlaysDeterministically(recorded_snap));
  return snap_maker.CheckTrace(recorded_snap, trace_options);
}

}  // namespace silifuzz
