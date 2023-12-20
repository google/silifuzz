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

#include <cstdlib>
#include <iostream>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "./util/arch.h"
#include "./util/itoa.h"
#include "./util/platform.h"

// The linter thinks "short" is a type.
ABSL_FLAG(bool, short, false, "Print only the platform ID.");  // NOLINT

namespace silifuzz {

int ToolMain(std::vector<char*>& positional_args) {
  PlatformId platform_id = CurrentPlatformId();

  if (absl::GetFlag(FLAGS_short)) {
    // Output only the current platform ID. Used by shell scripts.
    if (platform_id != PlatformId::kUndefined) {
      std::cout << EnumStr(platform_id) << std::endl;
    } else {
      std::cerr << "Unsupported platform" << std::endl;
    }
  } else {
    // A more verbose output for humans.
    // Arch is "obvious" / baked into the ELF file, but we may as well output
    // it to assist bug reports, etc.
    std::cout << "Arch:     " << Host::arch_name << std::endl;
    std::cout << "Platform: " << EnumStr(platform_id) << std::endl;
  }

  return platform_id == PlatformId::kUndefined ? EXIT_FAILURE : EXIT_SUCCESS;
}

}  // namespace silifuzz

int main(int argc, char* argv[]) {
  std::vector<char*> positional_args = absl::ParseCommandLine(argc, argv);
  return silifuzz::ToolMain(positional_args);
}
