// Copyright 2023 The SiliFuzz Authors.
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

#include <cstdint>
#include <cstdlib>
#include <optional>
#include <string>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "./tracing/analysis.h"
#include "./tracing/capstone_disassembler.h"
#include "./tracing/unicorn_tracer.h"
#include "./util/arch.h"
#include "./util/bitops.h"
#include "./util/checks.h"
#include "./util/enum_flag.h"
#include "./util/line_printer.h"
#include "./util/tool_util.h"

namespace silifuzz {
DEFINE_ENUM_FLAG(ArchitectureId);
}

ABSL_FLAG(silifuzz::ArchitectureId, arch, silifuzz::ArchitectureId::kUndefined,
          "Target architecture for raw snippets");

ABSL_FLAG(std::optional<std::string>, snippet, std::nullopt,
          "Path to a raw snippet");

ABSL_FLAG(size_t, max_instructions, 0x1000,
          "The maximum number of instructions that should be executed");

namespace silifuzz {

// Print information that can help a human understand the dynamic behavior of
// the code.
template <typename Arch>
absl::Status PrintTrace(UnicornTracer<Arch>& tracer, size_t max_instructions,
                        LinePrinter& out) {
  CapstoneDisassembler disas(Arch::architecture_id);
  uint64_t instruction_count = 0;
  uint64_t code_start = tracer.GetCurrentInstructionPointer();
  bool last_valid = false;
  uint64_t expected_next = 0;
  uint8_t insn_buffer[16];

  UContext<Arch> first, prev, zero_one, one_zero;
  tracer.GetRegisters(first);
  prev = first;
  ClearBits(zero_one);
  ClearBits(one_zero);

  tracer.SetInstructionCallback(
      [&](UnicornTracer<Arch>* tracer, uint64_t address, size_t max_size) {
        UContext<Arch> current;
        tracer->GetRegisters(current);
        AccumulateToggle(prev, current, zero_one, one_zero);
        prev = current;

        // TODO(ncbray): extract the register state and print diffs.
        // Did we see something other than linear execution?
        if (last_valid && address != expected_next) {
          out.Line("    branch");
        }

        // Disassemble the instruction
        CHECK(max_size < sizeof(insn_buffer));
        tracer->ReadMemory(address, insn_buffer, max_size);
        bool valid = disas.Disassemble(address, insn_buffer, max_size);

        // Display information about the next instruction.
        // Note: formatting assumes the code addresses are in the lower 4GB so
        // that it can omit 8 leading zeros and be a bit prettier.
        out.Line(absl::Dec(instruction_count, absl::kZeroPad4),
                 " addr=", absl::Hex(address, absl::kZeroPad8),
                 " offset=", absl::Dec(address - code_start, absl::kZeroPad4),
                 " size=", absl::Dec(disas.InstructionSize(), absl::kZeroPad2),
                 "    ", disas.FullText());
        instruction_count++;
        last_valid = valid;
        expected_next = address + disas.InstructionSize();
      });
  absl::Status result = tracer.Run(max_instructions);
  out.Line();
  out.Line("Register toggle 0=>1: ", PopCount(zero_one),
           " 1=>0: ", PopCount(one_zero));
  UContext<Arch> diff;
  BitDiff(first, prev, diff);
  out.Line("Final register hamming distance: ", PopCount(diff));
  return result;
}

template <typename Arch>
absl::Status PrintSnippetTrace(std::string& instructions,
                               size_t max_instructions, LinePrinter& out) {
  UnicornTracer<Arch> tracer;
  RETURN_IF_NOT_OK(tracer.InitSnippet(instructions));
  return PrintTrace(tracer, max_instructions, out);
}

absl::StatusOr<int> Print(std::vector<char*>& positional_args, LinePrinter& out,
                          LinePrinter& err) {
  std::optional<std::string> snippet_path = absl::GetFlag(FLAGS_snippet);
  if (snippet_path.has_value()) {
    ArchitectureId arch = absl::GetFlag(FLAGS_arch);
    if (arch == ArchitectureId::kUndefined) {
      return absl::InvalidArgumentError("--arch is required for snippets.");
    }
    if (!positional_args.empty()) {
      return absl::InvalidArgumentError("Too many positional arguments.");
    }
    size_t max_instructions = absl::GetFlag(FLAGS_max_instructions);
    ASSIGN_OR_RETURN_IF_NOT_OK(std::string instructions,
                               GetFileContents(snippet_path.value()));
    RETURN_IF_NOT_OK(ARCH_DISPATCH(PrintSnippetTrace, arch, instructions,
                                   max_instructions, out));
    return EXIT_SUCCESS;
  } else {
    return absl::InvalidArgumentError("Must specify an input.");
  }
}

template <typename Arch>
absl::Status AnalyzeSnippet(const std::string& instructions,
                            size_t max_instructions, LinePrinter& out) {
  ASSIGN_OR_RETURN_IF_NOT_OK(
      FaultInjectionResult result,
      AnalyzeSnippetWithFaultInjection<Arch>(instructions, max_instructions));
  out.Line("Detected ", result.fault_detection_count, "/",
           result.fault_injection_count, " faults - ",
           static_cast<int>(100 * result.sensitivity), "% sensitive");
  return absl::OkStatus();
}

absl::StatusOr<int> Analyze(std::vector<char*>& positional_args,
                            LinePrinter& out, LinePrinter& err) {
  std::optional<std::string> snippet_path = absl::GetFlag(FLAGS_snippet);
  if (snippet_path.has_value()) {
    ArchitectureId arch = absl::GetFlag(FLAGS_arch);
    if (arch == ArchitectureId::kUndefined) {
      return absl::InvalidArgumentError("--arch is required for snippets.");
    }
    if (!positional_args.empty()) {
      return absl::InvalidArgumentError("Too many positional arguments.");
    }
    size_t max_instructions = absl::GetFlag(FLAGS_max_instructions);
    ASSIGN_OR_RETURN_IF_NOT_OK(std::string instructions,
                               GetFileContents(snippet_path.value()));
    RETURN_IF_NOT_OK(ARCH_DISPATCH(AnalyzeSnippet, arch, instructions,
                                   max_instructions, out));
    return EXIT_SUCCESS;
  } else {
    return absl::InvalidArgumentError("Must specify an input.");
  }
}

constexpr Subcommand subcommands[] = {
    {
        .name = "print",
        .func = Print,
    },
    {
        .name = "analyze",
        .func = Analyze,
    },
};

}  // namespace silifuzz

extern "C" int main(int argc, char** argv) {
  return silifuzz::SubcommandMain(
      argc, argv, "trace_tool",
      absl::Span<const silifuzz::Subcommand>(silifuzz::subcommands));
}
