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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_TOOL_UTIL_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_TOOL_UTIL_H_

#include <optional>
#include <string>
#include <vector>

#include "absl/base/attributes.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "./util/line_printer.h"

// This library contains some common constants and helpers for various
// SiliFuzz tools.

namespace silifuzz {

// Default name of the snapshot proto file to read/write.
static constexpr char kDefaultSnapshotFileName[] =
    "/tmp/silifuzz_snapshot.pbdata";

// Converts success status to process exit code for main().
inline int ToExitCode(bool success) { return success ? 0 : 1; }

// Returns first arg from *argv and adjusts *argc and *argv to skip it.
const char* ConsumeArg(std::vector<char*>& args);

// Returns iff argc, argv still contains args (that we no longer expect)
// and logs the error.
bool ExtraArgs(const std::vector<char*>& args);

// Read all the bytes of a file.
absl::StatusOr<std::string> GetFileContents(absl::string_view file_name);

// The entrypoint for a specific subcommand.
// This function can either return a exit code (0 for success, non-zero for
// failure) or a status that will be printed and turned into a failure exit
// code.
typedef absl::StatusOr<int> (*SubcommandFunc)(
    std::vector<char*>& positional_args, LinePrinter& out, LinePrinter& err);

// A named subcommand that this tool provides.
struct Subcommand {
  const char* name;
  SubcommandFunc func;
};

// A generic function that parses the command line and dispatches to a specific
// subcommand based on the first positional argument.
// Returns the exit code for the subcommand that was invoked. The caller is
// responsible for making this the exit code of the tool. See SUBCOMMAND_MAIN
// for an example of how to use this function.
int SubcommandMain(int argc, char** argv, const char* tool_name,
                   absl::Span<const Subcommand> subcommands)
    ABSL_MUST_USE_RESULT;

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_TOOL_UTIL_H_
