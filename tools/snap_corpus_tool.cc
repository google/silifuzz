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

// A tool to handle relocatable corpus files.
//
// Sample usage
//
//  # Extract snapshot with id my_snap and write it to output.pb
//  snap_corpus_tool extract <corpus_file> <my_snap> <output.pb>
//
//  # Print diff of actual vs expected end state
//  snap_corpus_tool end_state_diff <corpus_file> <BinaryLogEntry.pb>
//
//  # List all snaps in the corpus
//  snap_corpus_tool list_snaps <corpus_file>
//
#include <sys/mman.h>

#include <cstdint>
#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

#include "absl/flags/parse.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./common/snapshot.h"
#include "./common/snapshot_printer.h"
#include "./common/snapshot_util.h"
#include "./player/player_result_proto.h"
#include "./proto/binary_log_entry.pb.h"
#include "./proto/snapshot_execution_result.pb.h"
#include "./snap/snap.h"
#include "./snap/snap_corpus_util.h"
#include "./snap/snap_util.h"
#include "./util/checks.h"
#include "./util/line_printer.h"
#include "./util/platform.h"
#include "./util/proto_util.h"

namespace silifuzz {
namespace {

// Consumes pops a single arg from the front of the list and returns it.
absl::string_view ConsumeArg(std::vector<char*>& args) {
  CHECK(!args.empty());
  auto rv = args.front();
  args.erase(args.begin());
  return rv;
}

absl::StatusOr<const Snap*> FindSnap(const SnapCorpus* corpus,
                                     absl::string_view snap_id) {
  for (const Snap* snap : corpus->snaps) {
    if (snap->id == snap_id) {
      return snap;
    }
  }
  return absl::NotFoundError(absl::StrCat("Snap ", snap_id, " not found"));
}

absl::StatusOr<const Snap*> FindSnapByCodeAddress(const SnapCorpus* corpus,
                                                  uint64_t address) {
  for (const Snap* snap : corpus->snaps) {
    for (const auto& mapping : snap->memory_mappings) {
      if (address >= mapping.start_address &&
          address < mapping.start_address + mapping.num_bytes &&
          (mapping.perms & PROT_EXEC) != 0) {
        return snap;
      }
    }
  }
  return absl::NotFoundError(
      absl::StrCat("Address ", HexStr(address), " not found"));
}

absl::Status ToolMain(std::vector<char*>& args) {
  ConsumeArg(args);  // consume argv[0]
  std::string command = std::string(ConsumeArg(args));
  absl::string_view corpus_file = ConsumeArg(args);
  MmappedMemoryPtr<const SnapCorpus> corpus =
      LoadCorpusFromFile(corpus_file.data(), /* preload = */ false);

  LinePrinter lp(LinePrinter::StdErrPrinter);

  if (command == "extract") {
    if (args.size() < 2) {
      return absl::InvalidArgumentError("Too few arguments");
    }
    absl::string_view snap_id = ConsumeArg(args);
    ASSIGN_OR_RETURN_IF_NOT_OK(const Snap* snap,
                               FindSnap(corpus.get(), snap_id));
    absl::StatusOr<Snapshot> snapshot =
        SnapToSnapshot(*snap, CurrentPlatformId());
    RETURN_IF_NOT_OK(snapshot.status());
    absl::string_view output_file = ConsumeArg(args);
    RETURN_IF_NOT_OK(WriteSnapshotToFile(*snapshot, output_file));
    LOG_INFO("Wrote snap to ", output_file);
  } else if (command == "extract_code_address") {
    if (args.size() < 2) {
      return absl::InvalidArgumentError("Too few arguments");
    }
    absl::string_view arg = ConsumeArg(args);
    uint64_t address;
    if (!absl::SimpleHexAtoi(arg, &address)) {
      return absl::InvalidArgumentError(absl::StrCat("Invalid address ", arg));
    }
    ASSIGN_OR_RETURN_IF_NOT_OK(const Snap* snap,
                               FindSnapByCodeAddress(corpus.get(), address));
    absl::StatusOr<Snapshot> snapshot =
        SnapToSnapshot(*snap, CurrentPlatformId());
    RETURN_IF_NOT_OK(snapshot.status());
    absl::string_view output_file = ConsumeArg(args);
    RETURN_IF_NOT_OK(WriteSnapshotToFile(*snapshot, output_file));
    LOG_INFO("Wrote snap to ", output_file);
  } else if (command == "end_state_diff") {
    proto::BinaryLogEntry binary_log_entry;
    RETURN_IF_NOT_OK(ReadFromFile(ConsumeArg(args), &binary_log_entry));

    if (!binary_log_entry.has_snapshot_execution_result()) {
      return absl::InvalidArgumentError(
          "This BinaryLogProto isn't SnapshotExecutionResult");
    }
    proto::SnapshotExecutionResult result =
        binary_log_entry.snapshot_execution_result();
    ASSIGN_OR_RETURN_IF_NOT_OK(const Snap* snap,
                               FindSnap(corpus.get(), result.snapshot_id()));

    SnapshotPrinter printer(&lp);
    ASSIGN_OR_RETURN_IF_NOT_OK(Snapshot snapshot,
                               SnapToSnapshot(*snap, CurrentPlatformId()));
    ASSIGN_OR_RETURN_IF_NOT_OK(auto player_result, PlayerResultProto::FromProto(
                                                       result.player_result()));
    lp.Line(
        "Outcome = ",
        result.player_result().Outcome_Name(result.player_result().outcome()),
        " snapshot = ", result.snapshot_id(), " on CPU ", player_result.cpu_id);
    printer.PrintActualEndState(snapshot, *player_result.actual_end_state);
  } else if (command == "list_snaps") {
    for (const Snap* snap : corpus->snaps) {
      lp.Line(snap->id);
    }
    lp.Line("Total ", corpus->snaps.size);
  } else {
    return absl::InvalidArgumentError(
        absl::StrCat("Unknown command ", command));
  }
  return absl::OkStatus();
}

}  // namespace
}  // namespace silifuzz

int main(int argc, char* argv[]) {
  std::vector<char*> positional_args = absl::ParseCommandLine(argc, argv);

  absl::Status result = silifuzz::ToolMain(positional_args);
  if (!result.ok()) {
    LOG_ERROR(result.message());
  }

  return result.ok() ? EXIT_SUCCESS : EXIT_FAILURE;
}
