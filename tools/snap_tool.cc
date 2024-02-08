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

// A do-it-all tool for examining, manipulating, or creating
// snapshot proto files.

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/match.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./common/memory_state.h"
#include "./common/snapshot.h"
#include "./common/snapshot_file_util.h"
#include "./common/snapshot_printer.h"
#include "./runner/driver/runner_driver.h"
#include "./runner/make_snapshot.h"
#include "./runner/runner_provider.h"
#include "./snap/gen/relocatable_snap_generator.h"
#include "./snap/gen/snap_generator.h"
#include "./util/arch.h"
#include "./util/checks.h"
#include "./util/enum_flag.h"
#include "./util/enum_flag_types.h"
#include "./util/file_util.h"
#include "./util/itoa.h"
#include "./util/line_printer.h"
#include "./util/mmapped_memory_ptr.h"
#include "./util/platform.h"
#include "./util/tool_util.h"
#include "./util/ucontext/serialize.h"
#include "./util/ucontext/ucontext_types.h"

namespace silifuzz {  // for ADL
DEFINE_ENUM_FLAG(SnapshotPrinter::RegsMode);
DEFINE_ENUM_FLAG(SnapshotPrinter::FPRegsMode);
DEFINE_ENUM_FLAG(SnapshotPrinter::EndRegsMode);
DEFINE_ENUM_FLAG(SnapshotPrinter::EndStateMode);
}  // namespace silifuzz

using silifuzz::SnapshotPrinter;

// Flags common to all commands that modify the snapshot:
ABSL_FLAG(bool, dry_run, false,
          "Whether commands that modify snapshot instead will only print it.");
ABSL_FLAG(bool, normalize, true,
          "Whether to also do Snapshot::NormalizeAll() of the output.");
ABSL_FLAG(bool, raw, false,
          "Whether the input is a raw sequence of instructions rather than a "
          "Snapshot.");

ABSL_FLAG(std::optional<std::string>, out, std::nullopt, "Output file path.");

// Flags that control `print` command (including in --dry_run mode):
ABSL_FLAG(SnapshotPrinter::RegsMode, regs, SnapshotPrinter::kNonZeroRegs,
          "Register printing mode. Values: all, non-0.");
ABSL_FLAG(SnapshotPrinter::FPRegsMode, fpregs, SnapshotPrinter::kAllFPRegs,
          "FP register printing mode. Values: all, ctrl, none.");
ABSL_FLAG(SnapshotPrinter::EndRegsMode, end_regs,
          SnapshotPrinter::kChangedEndRegs,
          "End state register printing mode. Values: all, changed.");
ABSL_FLAG(SnapshotPrinter::EndStateMode, end_states,
          SnapshotPrinter::kEndStateDiffs,
          "End state printing mode. Values: all, diffs.");
ABSL_FLAG(int64_t, bytes_limit, 200,
          "Limit on the number of bytes printed for one memory-bytes blob. "
          "-1 means no-limit.");
ABSL_FLAG(bool, stats, true, "Whether some summary stats are printed.");
ABSL_FLAG(bool, endpoints_only, false, "Whether to only print the endpoints.");
ABSL_FLAG(silifuzz::PlatformId, target_platform,
          silifuzz::PlatformId::kUndefined,
          "Target platform for commands like generate_corpus");

// ========================================================================= //

namespace silifuzz {

// Implements the `print` command.
void PrintSnapshot(const Snapshot& snapshot, LinePrinter* line_printer) {
  SnapshotPrinter::Options options;
  options.regs_mode = absl::GetFlag(FLAGS_regs);
  options.fp_regs_mode = absl::GetFlag(FLAGS_fpregs);
  options.end_state_regs_mode = absl::GetFlag(FLAGS_end_regs);
  options.end_state_mode = absl::GetFlag(FLAGS_end_states);
  options.bytes_limit = absl::GetFlag(FLAGS_bytes_limit);
  options.stats = absl::GetFlag(FLAGS_stats);

  SnapshotPrinter printer(line_printer, options);
  if (absl::GetFlag(FLAGS_endpoints_only)) {
    printer.PrintEndpointsOnly(snapshot);
  } else {
    printer.Print(snapshot);
  }
}

// Wrapper around WriteSnapshotToFileOrDie() that adds --normalize and
// --dry_run handling.
void OutputSnapshotOrDie(Snapshot&& snapshot, absl::string_view filename,
                         LinePrinter* line_printer) {
  if (absl::GetFlag(FLAGS_normalize)) snapshot.NormalizeAll();

  if (absl::GetFlag(FLAGS_dry_run)) {
    line_printer->Line("New snapshot state would be:");
    line_printer->Line("");
    PrintSnapshot(snapshot, line_printer);
  } else {
    CHECK_STATUS(snapshot.IsCompleteSomeState());
    WriteSnapshotToFileOrDie(snapshot, filename);
  }
}

// Turn a file containing raw instruction bytes into a Snapshot.
absl::StatusOr<Snapshot> CreateSnapshotFromRawInstructions(
    absl::string_view filename) {
  // Load the instructions.
  ASSIGN_OR_RETURN_IF_NOT_OK(std::string instructions,
                             GetFileContents(filename));
  return MakeRawInstructions(instructions, MakingConfig::Default());
}

absl::StatusOr<Snapshot> LoadSnapshot(absl::string_view filename, bool raw) {
  return raw ? CreateSnapshotFromRawInstructions(filename)
             : ReadSnapshotFromFile(filename);
}

// Implements `generate_corpus` command.
absl::Status GenerateCorpus(const std::vector<std::string>& input_protos,
                            bool raw, PlatformId platform_id, int out_fd,
                            LinePrinter* line_printer) {
  if (platform_id == PlatformId::kUndefined) {
    return absl::InvalidArgumentError(
        "generate_corpus requires a valid platform id");
  }
  ArchitectureId arch_id = PlatformArchitecture(platform_id);
  SnapifyOptions opts = SnapifyOptions::V2InputRunOpts(arch_id);
  opts.platform_id = platform_id;

  std::vector<Snapshot> snapified_corpus;

  for (const std::string& proto_path : input_protos) {
    ASSIGN_OR_RETURN_IF_NOT_OK_PLUS(
        auto snapshot, LoadSnapshot(proto_path, raw), "Cannot read snapshot");
    auto snapified_or = Snapify(snapshot, opts);
    if (!snapified_or.ok()) {
      line_printer->Line("Skipping ", proto_path, ": ",
                         snapified_or.status().message());
      continue;
    }
    snapified_corpus.push_back(std::move(snapified_or).value());
  }
  if (snapified_corpus.empty()) {
    return absl::InvalidArgumentError("No usable Snapshots found");
  }

  // TODO(ksteuck): Call PartitionSnapshots() to ensure there are no conflicts.

  RelocatableSnapGeneratorOptions options;
  MmappedMemoryPtr<char> buffer =
      GenerateRelocatableSnaps(arch_id, snapified_corpus, options);
  absl::string_view buf(buffer.get(), MmappedMemorySize(buffer));
  if (!WriteToFileDescriptor(out_fd, buf)) {
    return absl::InternalError("WriteToFileDescriptor failed");
  }
  return absl::OkStatus();
}

absl::Status GetInstructions(const Snapshot& snapshot, int out_fd) {
  // The initial RIP / PC should point to first instruction
  uint64_t begin_code = snapshot.ExtractRip(snapshot.registers());

  // The end point should point to the beginning of the exit sequence.
  // This is also the end of the instructions that are unique to this Snapshot.
  // Trimming the exit sequence means that we should be able to re-make these
  // instructions and get the same snapshot.
  const Snapshot::EndStateList& end_states = snapshot.expected_end_states();
  if (end_states.empty()) {
    return absl::InternalError("Expected at least 1 end state");
  }
  uint64_t end_code = end_states[0].endpoint().instruction_address();
  CHECK_LE(begin_code, end_code);
  for (const Snapshot::EndState& es : end_states) {
    uint64_t other_end_code = es.endpoint().instruction_address();
    if (end_code != other_end_code) {
      return absl::InternalError(
          absl::StrCat("Endpoint position is inconsistent between endstates: ",
                       HexStr(end_code), " vs. ", HexStr(other_end_code)));
    }
  }

  // Normalizing the memory bytes should ensure all the instructions are inside
  // a single MemoryBytes object.
  Snapshot::MemoryBytesList memory_bytes = snapshot.memory_bytes();
  Snapshot::NormalizeMemoryBytes(snapshot.mapped_memory_map(), &memory_bytes);

  // Search for the instructions.
  for (const Snapshot::MemoryBytes& bytes : memory_bytes) {
    if (begin_code >= bytes.start_address() &&
        end_code <= bytes.limit_address()) {
      uint64_t begin_index = begin_code - bytes.start_address();
      absl::string_view view(bytes.byte_values().data() + begin_index,
                             end_code - begin_code);
      if (!WriteToFileDescriptor(out_fd, view)) {
        return absl::InternalError("WriteToFileDescriptor failed");
      }
      return absl::OkStatus();
    }
  }

  return absl::InternalError("Could not find instructions in the memory bytes");
}

// Actual implementation is platforms-specific. See x86_64/snap_tool_trace.cc
absl::Status Trace(const Snapshot& snapshot, PlatformId platform_id,
                   LinePrinter* line_printer);

absl::StatusOr<Snapshot> SetBytes(const Snapshot& snapshot,
                                  const Snapshot::MemoryBytes& memory_bytes) {
  MemoryState memory_state =
      MemoryState::MakeInitial(snapshot, MemoryState::kZeroMappedBytes);
  if (!memory_state.mapped_memory().Contains(memory_bytes.start_address(),
                                             memory_bytes.limit_address())) {
    return absl::OutOfRangeError(
        absl::StrCat("The range [", HexStr(memory_bytes.start_address()), ";",
                     HexStr(memory_bytes.limit_address()),
                     ") isn't mapped by the snapshot"));
  }
  memory_state.SetMemoryBytes(memory_bytes);
  Snapshot::MemoryBytesList memory_bytes_list =
      memory_state.memory_bytes_list(memory_state.written_memory());

  Snapshot copy = snapshot.Copy();
  RETURN_IF_NOT_OK(copy.ReplaceMemoryBytes(std::move(memory_bytes_list)));
  return copy;
}

template <typename Arch>
absl::StatusOr<Snapshot> SetInstructionPointerImpl(const Snapshot& snapshot,
                                                   Snapshot::Address pc) {
  GRegSet<Arch> gregs;
  const Snapshot::RegisterState& current_regs = snapshot.registers();
  if (!DeserializeGRegs(current_regs.gregs(), &gregs)) {
    return absl::InvalidArgumentError("Failed to deserialize gregs");
  }
  gregs.SetInstructionPointer(pc);
  std::string serialized_gregs;
  if (!SerializeGRegs(gregs, &serialized_gregs)) {
    return absl::InternalError("Failed to serialize gregs");
  }
  auto new_regs =
      Snapshot::RegisterState(serialized_gregs, current_regs.fpregs());
  RETURN_IF_NOT_OK(snapshot.can_set_registers(new_regs));
  Snapshot copy = snapshot.Copy();
  copy.set_registers(new_regs);
  return copy;
}

absl::StatusOr<int> OpenOutput() {
  std::optional<std::string> out = absl::GetFlag(FLAGS_out);
  if (out.has_value()) {
    int fd = open(out.value().c_str(), O_WRONLY | O_CREAT | O_TRUNC,
                  S_IRUSR | S_IWUSR);
    if (fd == -1) {
      return absl::UnknownError(
          absl::StrCat("Could not open ", out->c_str(), ": ", ErrnoStr(errno)));
    }
    return fd;
  }
  // Default to STDOUT - tool's original behavior.
  return dup(STDOUT_FILENO);
}

std::string OutputPath(absl::string_view input_path) {
  std::optional<std::string> out = absl::GetFlag(FLAGS_out);
  if (out.has_value()) {
    return out.value();
  }
  // Default to overwriting the input - tool's original behavior.
  return std::string(input_path);
}

// ========================================================================= //

// Implements main().
// args are the non-flag arguments.
// Returns success status.
bool SnapToolMain(std::vector<char*>& args) {
  LinePrinter line_printer(LinePrinter::StdErrPrinter);

  std::string command;
  std::string snapshot_file;
  if (args.size() < 2) {
    line_printer.Line(
        "Expected one of "
        "{print,set_id,set_end,make,play,generate_corpus,get_instructions,"
        "trace,set_bytes,set_pc} and a snapshot file name(s).");
    return false;
  } else {
    command = ConsumeArg(args);
    snapshot_file = ConsumeArg(args);
  }

  PlatformId platform_id = absl::GetFlag(FLAGS_target_platform);
  bool raw = absl::GetFlag(FLAGS_raw);
  // In raw mode it's reasonable to default to the current platform.
  if (raw && platform_id == PlatformId::kUndefined) {
    platform_id = CurrentPlatformId();
  }

  // Load the snapshot
  absl::StatusOr<Snapshot> snapshot_or = LoadSnapshot(snapshot_file, raw);
  if (!snapshot_or.ok()) {
    line_printer.Line("Could not load snapshot: ",
                      snapshot_or.status().ToString());
    return false;
  }
  Snapshot snapshot = std::move(snapshot_or).value();

  if (command == "print") {
    if (ExtraArgs(args)) return false;

    PrintSnapshot(snapshot, &line_printer);
  } else if (command == "set_id") {
    if (args.size() != 1) {
      line_printer.Line("Expected one snapshot id value argument.");
      return false;
    }
    std::string id = ConsumeArg(args);

    if (absl::Status s = Snapshot::IsValidId(id); !s.ok()) {
      line_printer.Line("Invalid snapshot id value: ", s.ToString());
      return false;
    }

    snapshot.set_id(id);

    OutputSnapshotOrDie(std::move(snapshot), OutputPath(snapshot_file),
                        &line_printer);
  } else if (command == "set_end") {
    // This is a way to manually replace snapshot's end-state(s) by one
    // specific endpoint address. It can be used to help one inspect
    // intermediate state of snapshot's execution.
    if (args.size() != 1) {
      line_printer.Line("Expected one endpoint hex address argument.");
      return false;
    }
    std::string addr = ConsumeArg(args);
    Snapshot::Address ep_addr;
    if (!absl::SimpleHexAtoi<Snapshot::Address>(addr, &ep_addr)) {
      line_printer.Line("Can't parse endpoint hex address: ", addr);
      return false;
    }

    Snapshot::Endpoint ep(ep_addr);
    Snapshot::EndState es(ep);
    auto s = snapshot.can_add_expected_end_state(es);
    if (!s.ok()) {
      line_printer.Line("Bad endpoint address value: ", addr, ": ",
                        s.message());
      return false;
    }
    snapshot.set_expected_end_states({es});

    OutputSnapshotOrDie(std::move(snapshot), OutputPath(snapshot_file),
                        &line_printer);
  } else if (command == "play") {
    if (ExtraArgs(args)) return false;

    absl::StatusOr<RunnerDriver> runner_or =
        RunnerDriverFromSnapshot(snapshot, RunnerLocation());

    if (!runner_or.ok()) {
      line_printer.Line("Could not play snapshot: ",
                        runner_or.status().ToString());
    }
    auto result_or = runner_or->PlayOne(snapshot.id());
    if (!result_or.ok()) {
      line_printer.Line("Could not play snapshot: ",
                        result_or.status().ToString());
      return false;
    }
    if (result_or->success()) {
      line_printer.Line("Snapshot played successfully.");
      return true;
    } else {
      RunnerDriver::PlayerResult player_result = result_or->player_result();
      line_printer.Line("Snapshot played with outcome = ",
                        EnumStr(player_result.outcome));
      line_printer.Line("Actual end state reached:");
      SnapshotPrinter printer(&line_printer);
      printer.PrintActualEndState(snapshot,
                                  *result_or->player_result().actual_end_state);
      return false;
    }
  } else if (command == "make") {
    if (ExtraArgs(args)) return false;

    absl::StatusOr<Snapshot> recorded_snapshot =
        MakeSnapshot(snapshot, MakingConfig::Default());
    if (!recorded_snapshot.ok()) {
      line_printer.Line(recorded_snapshot.status().ToString());
      return false;
    }

    line_printer.Line("Re-made snapshot succefully.");
    OutputSnapshotOrDie(std::move(recorded_snapshot).value(),
                        OutputPath(snapshot_file), &line_printer);
  } else if (command == "generate_corpus") {
    std::vector<std::string> inputs({snapshot_file});
    for (const auto& a : args) {
      inputs.push_back(a);
    }
    absl::StatusOr<int> out_fd = OpenOutput();
    if (!out_fd.ok()) {
      line_printer.Line(out_fd.status().ToString());
      return false;
    }
    absl::Status s =
        GenerateCorpus(inputs, raw, platform_id, out_fd.value(), &line_printer);
    close(out_fd.value());
    if (!s.ok()) {
      line_printer.Line("Cannot generate corpus: ", s.message());
      return false;
    }
  } else if (command == "set_bytes") {
    // Overwrite bytes in existing memory mappings of the snapshot.
    //
    // Sample invocation:
    //   snap_tool set_bytes snapshot.pb 0x123456000 '\x90\x66'
    // This will overwrite bytes starting at 0x123456000 to 0x90, 0x66.
    // Bails if the the address isn't mapped (i.e. won't add new mappings).
    std::string addr = ConsumeArg(args);
    Snapshot::Address target_addr;
    if (!absl::SimpleHexAtoi<Snapshot::Address>(addr, &target_addr)) {
      line_printer.Line("Can't parse memory address: ", addr);
      return false;
    }
    std::string escaped_data = ConsumeArg(args);
    std::string data;
    std::string err;
    if (!absl::StrContains(escaped_data, "\\")) {
      line_printer.Line(
          "Didn't find any escape sequences in the data. Make sure you quoted "
          "the input string correctly");
      return false;
    }
    if (!absl::CUnescape(escaped_data, &data, &err)) {
      line_printer.Line("Bad C-escaped data: ", err);
      return false;
    }
    if (ExtraArgs(args)) return false;
    absl::StatusOr<Snapshot> modified =
        SetBytes(snapshot, Snapshot::MemoryBytes(target_addr, data));
    if (!modified.ok()) {
      line_printer.Line("set_bytes: ", modified.status().message());
      return false;
    }
    OutputSnapshotOrDie(std::move(modified).value(), OutputPath(snapshot_file),
                        &line_printer);
  } else if (command == "set_pc") {
    // Set initial PC (%RIP on x86) to the specified value. Useful during
    // snapshot minimization to skip initial NOP instructions.
    //
    // Sample invocation:
    //   snap_tool set_pc snapshot.pb 0x123456000
    // This will set the initial PC to 0x123456000
    std::string pc_str = ConsumeArg(args);
    Snapshot::Address pc;
    if (!absl::SimpleHexAtoi<Snapshot::Address>(pc_str, &pc)) {
      line_printer.Line("Can't parse PC value: ", pc_str);
      return false;
    }
    if (ExtraArgs(args)) return false;
    absl::StatusOr<Snapshot> modified = ARCH_DISPATCH(
        SetInstructionPointerImpl, snapshot.architecture_id(), snapshot, pc);

    if (!modified.ok()) {
      line_printer.Line("set_pc: ", modified.status().message());
      return false;
    }
    OutputSnapshotOrDie(std::move(modified).value(), OutputPath(snapshot_file),
                        &line_printer);
  } else if (command == "trace") {
    if (ExtraArgs(args)) return false;
    PlatformId platform_id = absl::GetFlag(FLAGS_target_platform);
    if (platform_id == PlatformId::kUndefined) {
      platform_id = CurrentPlatformId();
    }
    if (absl::Status s = Trace(snapshot, platform_id, &line_printer); !s.ok()) {
      line_printer.Line("trace: ", s.message());
      return false;
    }
  } else if (command == "get_instructions") {
    absl::StatusOr<int> out_fd = OpenOutput();
    if (!out_fd.ok()) {
      line_printer.Line(out_fd.status().ToString());
      return false;
    }
    absl::Status s = GetInstructions(snapshot, out_fd.value());
    close(out_fd.value());
    if (!s.ok()) {
      line_printer.Line("Cannot get instructions: ", s.message());
      return false;
    }
  } else {
    line_printer.Line("Unknown command is given: ", command);
    return false;
  }
  return true;
}

}  // namespace silifuzz

// ========================================================================= //

int main(int argc, char** argv) {
  std::string usage =
      absl::StrCat(argv[0], " command snapshot-file-name [command arg(s)]");
  std::vector<char*> positional_args = absl::ParseCommandLine(argc, argv);
  silifuzz::ConsumeArg(positional_args);  // skip binary's name
  bool success = silifuzz::SnapToolMain(positional_args);
  return silifuzz::ToExitCode(success);
}
