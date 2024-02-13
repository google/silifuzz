// Copyright 2024 The SiliFuzz Authors.
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

#include "./util/testing/vsyscall.h"

#include <fstream>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/str_split.h"

namespace silifuzz {

namespace {

// Helper of VSyscallRegionReadable() below.  Called once only.
absl::StatusOr<bool> CheckVSyscallRegionReadable() {
  std::ifstream ifs("/proc/self/maps");
  if (!ifs) {
    return absl::InternalError("Failed to open /proc/self/maps");
  }
  std::string line;
  while (std::getline(ifs, line)) {
    if (absl::StrContains(line, "[vsyscall]")) {
      std::vector<std::string> parts =
          absl::StrSplit(line, ' ', absl::SkipEmpty());
      if (parts.size() < 2) {
        return absl::InternalError("Failed to parse /proc/self/maps");
      }
      const std::string& perms = parts[1];
      return absl::StrContains(perms, "r");
    }
  }
  if (ifs.bad()) {
    return absl::InternalError("Failed to read /proc/self/maps");
  }
  return false;
}

}  // namespace

absl::StatusOr<bool> VSyscallRegionReadable() {
  static absl::StatusOr<bool> readable = CheckVSyscallRegionReadable();
  return readable;
}

}  // namespace silifuzz
