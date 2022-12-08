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

#include "./util/data_dependency.h"

#include <filesystem>  // NOLINT(build/c++17)
#include <string>

#include "absl/strings/string_view.h"
#include "./util/checks.h"

namespace silifuzz {

std::string GetDataDependencyFilepath(absl::string_view relative_path) {
  return GetDataDependencyFilepathBazel(relative_path);
}

std::string GetDataDependencyFilepathBazel(absl::string_view relative_path) {
  std::filesystem::path p;
  if (auto test_dir = std::getenv("TEST_SRCDIR"); test_dir == nullptr) {
    p = std::filesystem::current_path() / relative_path;
  } else {
    p = std::filesystem::path(test_dir) / "silifuzz" / relative_path;
  }
  CHECK(std::filesystem::exists(p));
  return p;
}

}  // namespace silifuzz
