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

#include <filesystem>
#include <string>

namespace silifuzz {

namespace {
std::string GetDataDependencyFilepath(const std::string& relative_path) {
  // https://bazel.build/concepts/dependencies#data-dependencies
  // https://bazel.build/reference/test-encyclopedia
  auto test_dir = std::getenv("TEST_SRCDIR");
  if (test_dir == nullptr) {
    return std::filesystem::current_path() / relative_path;
  }
  return std::string(test_dir) + "/silifuzz/" + relative_path;
}
}  // namespace

std::string RunnerLocation() {
  return GetDataDependencyFilepath("runner/reading_runner_main_nolibc");
}

std::string RunnerTestHelperLocation() {
  return GetDataDependencyFilepath("runner/runner_test_helper_nolibc");
}

}  // namespace silifuzz
