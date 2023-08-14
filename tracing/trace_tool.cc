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
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "./tracing/analysis.h"
#include "./tracing/default_disassembler.h"
#include "./tracing/disassembler.h"
#include "./tracing/execution_trace.h"
#include "./tracing/unicorn_tracer.h"
#include "./util/arch.h"
#include "./util/bitops.h"
#include "./util/checks.h"
#include "./util/enum_flag.h"
#include "./util/line_printer.h"
#include "./util/tool_util.h"
#include "./util/ucontext/ucontext.h"

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

// Display the trace in a human-readable format with a bunch of metadata.
template <typename Arch>
void LogTrace(Disassembler& disasm, ExecutionTrace<Arch>& execution_trace,
              bool fault_injection, LinePrinter& out) {
  uint64_t expected_next = execution_trace.EntryAddress();
  bool last_valid = false;
  execution_trace.ForEach(
      [&](size_t index, UContext<Arch>& prev, InstructionInfo<Arch>& info) {
        bool valid = info.instruction_id != disasm.InvalidInstructionID();

        // Did we see something other than linear execution?
        if (last_valid && info.address != expected_next) {
          out.Line("    branch");
        }

        // Note: we disassemble the instruction a second time to recover the
        // full textual disassembly. In most cases we don't store this because
        // it's only needed for human-readable output.
        disasm.Disassemble(info.address, info.bytes, info.size);

        // Display information about the next instruction.
        // Note: formatting assumes the code addresses are in the lower 4GB so
        // that it can omit 8 leading zeros and be a bit prettier.
        std::string metadata = absl::StrCat(
            absl::Dec(index, absl::kZeroPad4),
            " addr=", absl::Hex(info.address, absl::kZeroPad8), " offset=",
            absl::Dec(info.address - execution_trace.EntryAddress(),
                      absl::kZeroPad4),
            " size=", absl::Dec(info.size, absl::kZeroPad2));

        // How many bits changed?
        UContext<Arch> diff;
        BitDiff(prev, info.ucontext, diff);
        // Ignore instruction pointer changes.
        diff.gregs.SetInstructionPointer(0);
        absl::StrAppend(&metadata,
                        " diff=", absl::Dec(PopCount(diff), absl::kZeroPad3));

        // Fault injection metrics.
        if (fault_injection) {
          absl::StrAppend(&metadata, " crit=", info.critical);
        }
        out.Line(metadata, "    ", disasm.FullText());

        last_valid = valid;
        expected_next = info.address + info.size;
      });
}

// Stats for a specific type of instruction in the trace.
template <typename Arch>
struct OpInfo {
  UContext<Arch> zero_one;
  UContext<Arch> one_zero;
  size_t critical;
  size_t count;

  void AddOp(UContext<Arch>& prev, InstructionInfo<Arch>& info) {
    AccumulateToggle(prev, info.ucontext, zero_one, one_zero);
    if (info.critical) {
      critical++;
    }
    count++;
  }

  void Finalize() {
    // The instruction pointer will toggle in arbitrary ways for all
    // instructions. Clear to reduce noise.
    zero_one.gregs.SetInstructionPointer(0);
    one_zero.gregs.SetInstructionPointer(0);
  }
};

// Stats for all the instructions in a trace.
template <typename Arch>
struct TraceOpInfo {
  std::vector<OpInfo<Arch>> op_infos;
  OpInfo<Arch> all_info;

  TraceOpInfo(size_t num_instruction_ids) : op_infos(num_instruction_ids) {
    memset(&op_infos[0], 0, op_infos.size() * sizeof(op_infos[0]));
    ClearBits(all_info);
  }
};

// Gather stats from a trace.
template <typename Arch>
TraceOpInfo<Arch> GatherTraceOpInfo(Disassembler& disasm,
                                    ExecutionTrace<Arch>& execution_trace) {
  TraceOpInfo<Arch> trace_info(disasm.NumInstructionIDs());

  // Gather information from the trace.
  execution_trace.ForEach(
      [&](size_t index, UContext<Arch>& prev, InstructionInfo<Arch>& info) {
        trace_info.op_infos[info.instruction_id].AddOp(prev, info);
        trace_info.all_info.AddOp(prev, info);
      });

  // Post process as needed.
  for (OpInfo<Arch>& info : trace_info.op_infos) {
    info.Finalize();
  }
  trace_info.all_info.Finalize();

  return trace_info;
}

// Display stats for a trace in a human-readable format.
template <typename Arch>
void LogTraceOpInfo(Disassembler& disasm, ExecutionTrace<Arch>& execution_trace,
                    bool fault_injection, LinePrinter& out) {
  // Summarize the trace.
  TraceOpInfo<Arch> trace_info = GatherTraceOpInfo(disasm, execution_trace);

  // Print the header.
  out.Line();
  std::string text =
      absl::StrFormat("%-12s %-5s %-5s %-5s", "op", "exec", "0=>1", "1=>0");
  if (fault_injection) {
    text = absl::StrFormat("%s %-5s", text, "crit%");
  }
  out.Line(text);
  out.Line();

  // Function for printing a line of the summary.
  auto log_info = [&](const std::string& name, const OpInfo<Arch>& info) {
    std::string text =
        absl::StrFormat("%-12s %5d %5d %5d", name, info.count,
                        PopCount(info.zero_one), PopCount(info.one_zero));
    if (fault_injection) {
      int critical = static_cast<int>(100.0f * info.critical / info.count);
      text = absl::StrFormat("%s %5d", text, critical);
    }
    out.Line(text);
  };

  // Print the summary for each type of op.
  for (size_t i = 0; i < trace_info.op_infos.size(); ++i) {
    OpInfo<Arch>& info = trace_info.op_infos[i];
    if (info.count > 0) {
      std::string name = disasm.InstructionIDName(i);
      log_info(name, info);
    }
  }

  // Print the aggregate summary.
  out.Line();
  log_info("total", trace_info.all_info);
}

// Print information that can help a human understand the dynamic behavior of
// the code.
template <typename Arch>
absl::Status PrintTrace(UnicornTracer<Arch>& tracer, size_t max_instructions,
                        LinePrinter& out) {
  DefaultDisassembler<Arch> disasm;
  ExecutionTrace<Arch> execution_trace(max_instructions);

  absl::Status result = CaptureTrace(tracer, disasm, execution_trace);

  LogTrace(disasm, execution_trace, false, out);
  LogTraceOpInfo(disasm, execution_trace, false, out);
  out.Line();
  UContext<Arch> diff;
  BitDiff(execution_trace.FirstContext(), execution_trace.LastContext(), diff);
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
  DefaultDisassembler<Arch> disasm;
  ExecutionTrace<Arch> execution_trace(max_instructions);
  UnicornTracer<Arch> tracer;
  RETURN_IF_NOT_OK(tracer.InitSnippet(instructions));
  RETURN_IF_NOT_OK(CaptureTrace(tracer, disasm, execution_trace));

  ASSIGN_OR_RETURN_IF_NOT_OK(
      FaultInjectionResult result,
      AnalyzeSnippetWithFaultInjection<Arch>(instructions, execution_trace));
  out.Line("Detected ", result.fault_detection_count, "/",
           result.fault_injection_count, " faults - ",
           static_cast<int>(100 * result.sensitivity), "% sensitive");

  LogTrace(disasm, execution_trace, true, out);
  LogTraceOpInfo(disasm, execution_trace, true, out);

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
