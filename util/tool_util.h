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

#include "absl/strings/string_view.h"

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

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_TOOL_UTIL_H_
