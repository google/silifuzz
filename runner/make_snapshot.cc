// Copyright 2024 The SiliFuzz Authors.
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

#include "./runner/make_snapshot.h"

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./common/proxy_config.h"
#include "./common/raw_insns_util.h"
#include "./common/snapshot.h"
#include "./common/snapshot_enums.h"
#include "./player/trace_options.h"
#include "./runner/runner_provider.h"
#include "./runner/snap_maker.h"
#include "./util/arch.h"
#include "./util/checks.h"
#include "./util/itoa.h"

namespace silifuzz {

MakingConfig MakingConfig::Default() {
  return {
      .runner_path = RunnerLocation(),
      .trace = TraceOptions::Default(),
  };
}

MakingConfig MakingConfig::Quick() {
  MakingConfig config = MakingConfig::Default();
  config.num_verify_attempts = 1;
  return config;
}

absl::StatusOr<Snapshot> MakeSnapshot(const Snapshot& snapshot,
                                      const MakingConfig& making_config) {
  SnapMaker::Options opts;
  opts.runner_path = making_config.runner_path;
  opts.max_pages_to_add = making_config.max_pages_to_add;
  opts.num_verify_attempts = making_config.num_verify_attempts;
  SnapMaker maker(opts);

  ASSIGN_OR_RETURN_IF_NOT_OK_PLUS(Snapshot made_snapshot, maker.Make(snapshot),
                                  "Could not make snapshot: ");
  ASSIGN_OR_RETURN_IF_NOT_OK_PLUS(Snapshot recorded_snapshot,
                                  maker.RecordEndState(made_snapshot),
                                  "Could not record snapshot: ");

  DCHECK_EQ(recorded_snapshot.expected_end_states().size(), 1);
  const Snapshot::Endpoint& ep =
      recorded_snapshot.expected_end_states()[0].endpoint();
  if (ep.type() != snapshot_types::Endpoint::kInstruction) {
    return absl::InternalError(absl::StrCat(
        "Cannot fix ", EnumStr(ep.sig_cause()), "/", EnumStr(ep.sig_num())));
  }
  RETURN_IF_NOT_OK(maker.VerifyPlaysDeterministically(recorded_snapshot));
  return maker.CheckTrace(recorded_snapshot, making_config.trace);
}

absl::StatusOr<Snapshot> MakeRawInstructions(
    absl::string_view instructions, const MakingConfig& making_config,
    const FuzzingConfig<Host>& fuzzing_config) {
  // Create the initial snapshot.
  ASSIGN_OR_RETURN_IF_NOT_OK(
      Snapshot snapshot,
      InstructionsToSnapshot<Host>(instructions, fuzzing_config));
  snapshot.set_id(InstructionsToSnapshotId(instructions));

  // Make to add the exit sequence, etc.
  return MakeSnapshot(snapshot, making_config);
}

}  // namespace silifuzz
