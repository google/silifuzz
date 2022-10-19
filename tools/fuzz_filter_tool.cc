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

// This tool reads an instruction sequence as bytes from the input file and
// returns 0 exit code iff the sequence can be converted into a non-signalling
// SiliFuzz Snapshot.
// The bytes are converted into Snapshot using InstructionsToSnapshot() which
// is the same as what our fuzzers and the fix pipeline use.

#include <string>
#include <utility>
#include <vector>

#include "absl/flags/parse.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "./common/raw_insns_util.h"
#include "./common/snapshot.h"
#include "./common/snapshot_enums.h"
#include "./common/snapshot_util.h"
#include "./runner/runner_provider.h"
#include "./runner/snap_maker.h"
#include "./util/checks.h"
#include "./util/itoa.h"
#include "./util/path_util.h"
#include "./util/proto_util.h"
#include "./util/tool_util.h"

namespace silifuzz {
namespace {

bool FilterToolMain(absl::string_view raw_insns_file,
                    absl::string_view output_snapshot_file = "") {
  auto bytes = ReadFile(raw_insns_file);
  if (!bytes.ok()) {
    LOG_ERROR(bytes.status().message());
    return false;
  }
  absl::StatusOr<Snapshot> input_snapshot_or =
      InstructionsToSnapshot_X86_64(*bytes);
  if (!input_snapshot_or.ok()) {
    LOG_ERROR(input_snapshot_or.status().message());
    return false;
  }
  input_snapshot_or->set_id(std::string(Basename(raw_insns_file)));
  Snapshot input_snapshot = std::move(input_snapshot_or).value();
  auto WriteOutputFile = [&output_snapshot_file](
                             absl::Status s, const Snapshot& output_snapshot) {
    if (!s.ok()) {
      LOG_ERROR(s.message());
    }
    if (!output_snapshot_file.empty()) {
      WriteSnapshotToFileOrDie(output_snapshot, output_snapshot_file);
    }
    return false;
  };

  SnapMaker::Options opts;
  opts.runner_path = RunnerLocation();
  opts.num_verify_attempts = 1;
  opts.x86_filter_split_lock = true;
  SnapMaker maker(opts);

  absl::StatusOr<Snapshot> made_snapshot_or = maker.Make(input_snapshot);
  if (!made_snapshot_or.ok()) {
    return WriteOutputFile(made_snapshot_or.status(), input_snapshot);
  }
  Snapshot made_snapshot = std::move(made_snapshot_or).value();

  absl::StatusOr<Snapshot> recorded_snapshot_or =
      maker.RecordEndState(made_snapshot);
  if (!recorded_snapshot_or.ok()) {
    return WriteOutputFile(recorded_snapshot_or.status(), made_snapshot);
  }
  Snapshot recorded_snapshot = std::move(recorded_snapshot_or).value();

  WriteOutputFile(absl::OkStatus(), recorded_snapshot);
  DCHECK_EQ(recorded_snapshot.expected_end_states().size(), 1);
  const auto& ep = recorded_snapshot.expected_end_states()[0].endpoint();
  if (ep.type() != snapshot_types::Endpoint::kInstruction) {
    LOG_ERROR("Cannot fix ", EnumStr(ep.sig_cause()), "/",
              EnumStr(ep.sig_num()));
    return false;
  }
  absl::Status verify_status = maker.Verify(recorded_snapshot);
  if (!verify_status.ok()) {
    LOG_ERROR(verify_status.message());
  }
  return verify_status.ok();
}

}  // namespace
}  // namespace silifuzz

int main(int argc, char** argv) {
  std::vector<char*> non_flag_args = absl::ParseCommandLine(argc, argv);
  if (non_flag_args.size() < 2) {
    return 1;
  }
  absl::string_view output_snapshot_file = "";
  if (non_flag_args.size() > 2) {
    output_snapshot_file = non_flag_args[2];
  }
  bool success =
      silifuzz::FilterToolMain(non_flag_args[1], output_snapshot_file);
  return silifuzz::ToExitCode(success);
}
