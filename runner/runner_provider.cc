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

#include <string>

#include "./util/data_dependency.h"

namespace silifuzz {

std::string RunnerLocation() {
  return GetDataDependencyFilepath("runner/reading_runner_main_nolibc");
}

std::string RunnerTestHelperLocation() {
  return GetDataDependencyFilepath("runner/runner_test_helper_nolibc");
}

}  // namespace silifuzz
