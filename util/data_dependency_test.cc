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

#include <sys/stat.h>

#include <string>

#include "gtest/gtest.h"

namespace silifuzz {
namespace {

TEST(DataDependency, GetDataDependencyFilepath) {
  std::string filepath =
      GetDataDependencyFilepath("util/testdata/data_dependency_testdata");
  struct stat s;
  ASSERT_EQ(stat(filepath.c_str(), &s), 0);
}

TEST(DataDependency, GetDataDependencyFilepathBazel_NoFile) {
  EXPECT_DEATH_IF_SUPPORTED(
      GetDataDependencyFilepathBazel("util/testdata/bogus"),
      "std::filesystem::exists");
}

}  // namespace
}  // namespace silifuzz
