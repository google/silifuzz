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
#include <optional>
#include <string>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./common/snapshot.h"
#include "./common/snapshot_file_util.h"
#include "./common/snapshot_printer.h"
#include "./player/player_result_proto.h"
#include "./proto/binary_log_entry.pb.h"
#include "./proto/snapshot_execution_result.pb.h"
#include "./snap/snap.h"
#include "./snap/snap_corpus_util.h"
#include "./snap/snap_util.h"
#include "./util/arch.h"
#include "./util/checks.h"
#include "./util/enum_flag_types.h"
#include "./util/itoa.h"
#include "./util/line_printer.h"
#include "./util/mmapped_memory_ptr.h"
#include "./util/platform.h"
#include "./util/proto_util.h"

ABSL_FLAG(silifuzz::PlatformId, target_platform,
          silifuzz::PlatformId::kUndefined,
          "Target platform for commands like extract");

namespace silifuzz {
namespace {

// Consumes pops a single arg from the front of the list and returns it.
absl::string_view ConsumeArg(std::vector<char*>& args) {
  CHECK(!args.empty());
  auto rv = args.front();
  args.erase(args.begin());
  return rv;
}

template <typename Arch>
absl::StatusOr<const Snap<Arch>*> FindSnap(const SnapCorpus<Arch>* corpus,
                                           absl::string_view snap_id) {
  const Snap<Arch>* snap = corpus->Find(snap_id.data());
  if (snap == nullptr) {
    return absl::NotFoundError(absl::StrCat("Snap ", snap_id, " not found"));
  }
  return snap;
}

template <typename Arch>
absl::StatusOr<const Snap<Arch>*> FindSnapByCodeAddress(
    const SnapCorpus<Arch>* corpus, uint64_t address) {
  for (const Snap<Arch>* snap : corpus->snaps) {
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

template <typename Arch>
PlatformId GetTargetPlatform() {
  PlatformId platform_id = absl::GetFlag(FLAGS_target_platform);
  if (platform_id == PlatformId::kUndefined) {
    platform_id = CurrentPlatformId();
  }
  CHECK(PlatformArchitecture(platform_id) == Arch::architecture_id);
  return platform_id;
}

template <typename Arch>
absl::Status ToolMainImpl(absl::string_view command,
                          absl::string_view corpus_file,
                          std::vector<char*>& args) {
  MmappedMemoryPtr<const SnapCorpus<Arch>> corpus =
      LoadCorpusFromFile<Arch>(corpus_file.data(), /* preload = */ false);

  LinePrinter lp(LinePrinter::StdErrPrinter);

  if (command == "extract") {
    if (args.size() < 2) {
      return absl::InvalidArgumentError("Too few arguments");
    }
    absl::string_view snap_id = ConsumeArg(args);
    ASSIGN_OR_RETURN_IF_NOT_OK(const Snap<Arch>* snap,
                               FindSnap(corpus.get(), snap_id));
    absl::StatusOr<Snapshot> snapshot =
        SnapToSnapshot(*snap, GetTargetPlatform<Arch>());
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
    ASSIGN_OR_RETURN_IF_NOT_OK(const Snap<Arch>* snap,
                               FindSnapByCodeAddress(corpus.get(), address));
    absl::StatusOr<Snapshot> snapshot =
        SnapToSnapshot(*snap, GetTargetPlatform<Arch>());
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
    ASSIGN_OR_RETURN_IF_NOT_OK(const Snap<Arch>* snap,
                               FindSnap(corpus.get(), result.snapshot_id()));

    SnapshotPrinter printer(&lp);
    ASSIGN_OR_RETURN_IF_NOT_OK(
        Snapshot snapshot, SnapToSnapshot(*snap, GetTargetPlatform<Arch>()));
    ASSIGN_OR_RETURN_IF_NOT_OK(auto player_result, PlayerResultProto::FromProto(
                                                       result.player_result()));
    lp.Line(
        "Outcome = ",
        result.player_result().Outcome_Name(result.player_result().outcome()),
        " snapshot = ", result.snapshot_id(), " on CPU ", player_result.cpu_id);
    printer.PrintActualEndState(snapshot, *player_result.actual_end_state);
  } else if (command == "list_snaps") {
    for (const Snap<Arch>* snap : corpus->snaps) {
      lp.Line(snap->id);
    }
    lp.Line("Total ", corpus->snaps.size);
  } else {
    return absl::InvalidArgumentError(
        absl::StrCat("Unknown command ", command));
  }
  return absl::OkStatus();
}

absl::Status ToolMain(std::vector<char*>& args) {
  ConsumeArg(args);  // consume argv[0]
  std::string command = std::string(ConsumeArg(args));
  std::string corpus_file = std::string(ConsumeArg(args));
  ArchitectureId arch = CorpusFileArchitecture(corpus_file.data());
  return ARCH_DISPATCH(ToolMainImpl, arch, command, corpus_file, args);
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
