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

#include "./tools/fuzz_filter_tool.h"

#include <string>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "./common/raw_insns_util.h"
#include "./common/snapshot.h"
#include "./common/snapshot_enums.h"
#include "./runner/runner_provider.h"
#include "./runner/snap_maker.h"
#include "./util/checks.h"

namespace silifuzz {

absl::Status FilterToolMain(absl::string_view id,
                            absl::string_view raw_insns_bytes) {
  ASSIGN_OR_RETURN_IF_NOT_OK(Snapshot input_snapshot,
                             InstructionsToSnapshot<Host>(raw_insns_bytes));
  input_snapshot.set_id(std::string(id));
  SnapMaker::Options opts;
  opts.runner_path = RunnerLocation();
  opts.num_verify_attempts = 1;
  SnapMaker maker(opts);

  ASSIGN_OR_RETURN_IF_NOT_OK(Snapshot made_snapshot,
                             maker.Make(input_snapshot));

  ASSIGN_OR_RETURN_IF_NOT_OK(Snapshot recorded_snapshot,
                             maker.RecordEndState(made_snapshot));

  DCHECK_EQ(recorded_snapshot.expected_end_states().size(), 1);
  const Snapshot::Endpoint& ep =
      recorded_snapshot.expected_end_states()[0].endpoint();
  if (ep.type() != snapshot_types::Endpoint::kInstruction) {
    return absl::InvalidArgumentError(absl::StrCat(
        "Cannot fix ", EnumStr(ep.sig_cause()), "/", EnumStr(ep.sig_num())));
  }
  RETURN_IF_NOT_OK(maker.VerifyPlaysDeterministically(recorded_snapshot));
  return maker.CheckTrace(recorded_snapshot).status();
}

}  // namespace silifuzz
