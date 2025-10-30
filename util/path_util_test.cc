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

#include "./util/path_util.h"

#include <stdlib.h>

#include <csignal>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "./util/checks.h"
#include "./util/testing/status_macros.h"
#include "./util/testing/status_matchers.h"

namespace silifuzz {
namespace {
using silifuzz::testing::IsOkAndHolds;
using ::testing::EndsWith;
using ::testing::KilledBySignal;

TEST(PathUtil, Basename) {
  EXPECT_EQ("", Basename("/foo/"));
  EXPECT_EQ("foo", Basename("/foo"));
  EXPECT_EQ("bar", Basename("foo/bar"));
  EXPECT_EQ("", Basename("quux/"));
  EXPECT_EQ("baz", Basename("baz"));
  EXPECT_EQ("", Basename("/"));
  EXPECT_EQ("", Basename(""));
}

TEST(PathUtil, Dirname) {
  EXPECT_EQ("/hello", Dirname("/hello/"));
  EXPECT_EQ("/", Dirname("/hello"));
  EXPECT_EQ("/hello", Dirname("/hello/world"));
  EXPECT_EQ("hello", Dirname("hello/world"));
  EXPECT_EQ("hello", Dirname("hello/"));
  EXPECT_EQ("", Dirname("world"));
  EXPECT_EQ("/", Dirname("/"));
  EXPECT_EQ("", Dirname(""));
}

TEST(PathUtil, CreateTempFile) {
  // Normally the caller should remove the files. We are leaving them behind
  // since the files are created in $TEST_TMPDIR
  ASSERT_OK(CreateTempFile("test"));
  ASSERT_THAT(CreateTempFile("test", ".cc"), IsOkAndHolds(EndsWith(".cc")));
}

TEST(PathUtil, CreateTempFileFail) {
  auto test = []() {
    ::setenv("TEST_TMPDIR", "/bogus", 1);
    // Should crash with SIGABRT and print the contents of the status
    // checked by ASSERT_EXIT below.
    if (auto s = CreateTempFile("test"); !s.ok()) {
      LOG_INFO("File creation failed as expected");
      // Deref the failed status and cause SIGABRT
      auto v = *s;
    } else {
      // Must not happen. Let the subprocess finish successfully and ASSERT_EXIT
      // below fail.
    }
  };
  // The `test` above messes with the environment so we have to run it
  // in a separate process.
  ASSERT_EXIT(
      { test(); }, KilledBySignal(SIGABRT), "File creation failed as expected");
}

}  // namespace

}  // namespace silifuzz
