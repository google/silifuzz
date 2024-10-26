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
// returns 0 exit code iff the sequence can be converted into a Snap-compatible
// SiliFuzz Snapshot.
// The bytes are converted into Snapshot using InstructionsToSnapshot() which
// is the same as what our fuzzers and the fix pipeline use.

#include <string>
#include <vector>

#include "absl/flags/parse.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "./tools/fuzz_filter_tool.h"
#include "./util/checks.h"
#include "./util/tool_util.h"

int main(int argc, char** argv) {
  std::vector<char*> non_flag_args = absl::ParseCommandLine(argc, argv);
  if (non_flag_args.size() != 2) {
    LOG_ERROR("Expected exactly 1 input file");
    return 1;
  }
  absl::StatusOr<std::string> bytes =
      silifuzz::GetFileContents(non_flag_args[1]);
  if (!bytes.ok()) {
    LOG_ERROR(bytes.status().message());
    return 1;
  }
  absl::Status s = silifuzz::FilterToolMain(*bytes);
  if (!s.ok()) LOG_ERROR(s.message());
  return silifuzz::ToExitCode(s.ok());
}
