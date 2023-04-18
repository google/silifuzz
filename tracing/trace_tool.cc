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

#include <cstddef>
#include <cstdlib>
#include <optional>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/status/status.h"
#include "./tracing/unicorn_tracer.h"
#include "./util/arch.h"
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

template <typename Arch>
absl::Status PrintTrace(std::string& instructions, size_t max_instructions) {
  UnicornTracer<Arch> tracer;
  RETURN_IF_NOT_OK(tracer.InitSnippet(instructions));
  return tracer.Run(max_instructions);
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
    RETURN_IF_NOT_OK(
        ARCH_DISPATCH(PrintTrace, arch, instructions, max_instructions));
    out.Line("TODO: install a hook and actually print the trace.");
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
};

}  // namespace silifuzz

extern "C" int main(int argc, char** argv) {
  return silifuzz::SubcommandMain(
      argc, argv, "trace_tool",
      absl::Span<const silifuzz::Subcommand>(silifuzz::subcommands));
}
