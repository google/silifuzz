// Copyright 2023 The SiliFuzz Authors.
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

#include "./util/tool_util.h"

#include <unistd.h>

#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/string_view.h"
#include "./util/checks.h"
#include "./util/file_util.h"
#include "./util/path_util.h"
#include "./util/testing/status_macros.h"
#include "./util/testing/status_matchers.h"

namespace silifuzz {
namespace {

using ::silifuzz::testing::IsOkAndHolds;

TEST(ToolUtilTest, ToExitCode) {
  EXPECT_EQ(ToExitCode(/*success=*/true), 0);
  EXPECT_EQ(ToExitCode(/*success=*/false), 1);
}

TEST(ToolUtilTest, ConsumeArg) {
  std::string arg0 = "arg0";
  std::string arg1 = "arg1";
  std::string arg2 = "arg2";
  std::vector<char*> args = {arg0.data(), arg1.data(), arg2.data()};
  const char* removed_arg = ConsumeArg(args);
  EXPECT_EQ(removed_arg, arg0.c_str());
  std::vector<char*> expected_args = {arg1.data(), arg2.data()};
  EXPECT_EQ(args, expected_args);
}

TEST(ToolUtilTest, ExtraArgs) {
  std::string arg0 = "arg0";
  std::vector<char*> full_args = {arg0.data()};
  std::vector<char*> empty_args = {};
  EXPECT_EQ(ExtraArgs(full_args), true);
  EXPECT_EQ(ExtraArgs(empty_args), false);
}

TEST(ToolUtilTest, GetFileContents) {
  auto sor_filename = CreateTempFile("ToolUtilTest_GetFileContents");
  ASSERT_OK(sor_filename);
  std::string filename = sor_filename.value();
  const std::string contents = "contents";
  CHECK(SetContents(filename, contents));
  EXPECT_THAT(GetFileContents(filename), IsOkAndHolds(contents));
}

TEST(ToolUtilTest, GetSysfsFileContents) {
  auto sor_filename = CreateTempFile("ToolUtilTest_GetSysfsFileContents");
  ASSERT_OK(sor_filename);
  std::string filename = sor_filename.value();
  const char contents[] = {'c', 'o', '\0'};
  const std::string expected_contents = "co";
  CHECK(
      SetContents(filename, absl::string_view(contents, std::size(contents))));
  EXPECT_THAT(GetSysfsFileContents(filename), IsOkAndHolds(expected_contents));
}

}  // namespace
}  // namespace silifuzz
