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

#include "./runner/runner_provider.h"

#include <sys/stat.h>

#include <string>

#include "absl/flags/flag.h"
#include "./util/checks.h"
#include "./util/data_dependency.h"

ABSL_FLAG(std::string, runner, "", "Path to the runner binary.");

namespace silifuzz {

std::string RunnerLocation() {
  // Allow a command-line override.
  std::string runner = absl::GetFlag(FLAGS_runner);
  if (!runner.empty()) {
    return runner;
  }

  std::string loc =
      GetDataDependencyFilepath("runner/reading_runner_main_nolibc");
  struct stat s;
  if (stat(loc.c_str(), &s) < 0) {
    loc = "./reading_runner_main_nolibc";
  }
  if (stat(loc.c_str(), &s) < 0) {
    LOG(ERROR)
        << "Could not find runner binary. Try passing --runner=PATH/TO/RUNNER.";
  }
  return loc;
}

std::string RunnerTestHelperLocation() {
  return GetDataDependencyFilepath("runner/runner_test_helper_nolibc");
}

}  // namespace silifuzz
