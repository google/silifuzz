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

#include "./util/flag_matcher.h"

#include <cstring>

#include "./util/checks.h"
#include "./util/nolibc_gunit.h"

namespace silifuzz {
namespace {

// Helper class for command line argument testing.

TEST(FlagMatcher, Constructor) {
  constexpr int kArgc = 1;
  const char *kArgv[kArgc] = {"foo"};
  CommandLineFlagMatcher matcher(kArgc, kArgv);
  CHECK_EQ(matcher.optind(), 1);
  CHECK_EQ(matcher.optarg(), nullptr);
}

TEST(FlagMatcher, ConstructorNonConstPointers) {
  constexpr int kArgc = 2;
  constexpr int kMaxArgSize = 100;
  char non_const_arguments[kArgc][kMaxArgSize] = {
      {'f', 'o', 'o', '\0'},
      {'-', '-', 'b', 'a', 'r', '\0'},
  };
  char *argv[kArgc] = {
      non_const_arguments[0],
      non_const_arguments[1],
  };
  CommandLineFlagMatcher matcher(kArgc, argv);
  CHECK_EQ(matcher.optind(), 1);
  CHECK_EQ(matcher.optarg(), nullptr);
}

TEST(FlagMatcher, FlagWithoutArgument) {
  constexpr int kArgc = 3;
  const char *kArgv[kArgc] = {
      "foo", "--abc",
      "-abc",  // malformed with one '-'.
  };
  CommandLineFlagMatcher matcher(kArgc, kArgv);
  CHECK(!matcher.Match("xtz", CommandLineFlagMatcher::kNoArgument));
  CHECK(matcher.Match("abc", CommandLineFlagMatcher::kNoArgument));
  CHECK_EQ(matcher.optind(), 2);
  CHECK_EQ(matcher.optarg(), nullptr);
  // Needs 2 dashes.
  CHECK(!matcher.Match("abc", CommandLineFlagMatcher::kNoArgument));
}

TEST(FlagMatcher, FlagWithFollowingArgument) {
  constexpr int kArgc = 4;
  const char *kArgv[kArgc] = {"foo", "--abc", "123", "not-a-flag"};
  CommandLineFlagMatcher matcher(kArgc, kArgv);
  CHECK(matcher.Match("abc", CommandLineFlagMatcher::kRequiredArgument));
  CHECK_EQ(matcher.optind(), 3);
  CHECK_EQ(strcmp(matcher.optarg(), "123"), 0);
}

TEST(FlagMatcher, FlagWithEmbeddedArgument) {
  constexpr int kArgc = 3;
  const char *kArgv[kArgc] = {"foo", "--abc=123", "not-a-flag"};
  CommandLineFlagMatcher matcher(kArgc, kArgv);
  CHECK(matcher.Match("abc", CommandLineFlagMatcher::kRequiredArgument));
  CHECK_EQ(matcher.optind(), 2);
  CHECK_EQ(strcmp(matcher.optarg(), "123"), 0);
}

TEST(FlagMatcher, FlagWithEmptyArgument) {
  constexpr int kArgc = 3;
  const char *kArgv[kArgc] = {"foo", "--empty=", "--abc=123"};
  CommandLineFlagMatcher matcher(kArgc, kArgv);
  CHECK(matcher.Match("empty", CommandLineFlagMatcher::kRequiredArgument));
  CHECK_EQ(matcher.optind(), 2);
  CHECK_EQ(strcmp(matcher.optarg(), ""), 0);
  CHECK(matcher.Match("abc", CommandLineFlagMatcher::kRequiredArgument));
  CHECK_EQ(matcher.optind(), 3);
  CHECK_EQ(strcmp(matcher.optarg(), "123"), 0);
}

TEST(FlagMatcher, EndOfCommandLine) {
  constexpr int kArgc = 2;
  const char *kArgv[kArgc] = {"foo", "--abc"};
  CommandLineFlagMatcher matcher(kArgc, kArgv);
  CHECK(matcher.Match("abc", CommandLineFlagMatcher::kNoArgument));
  CHECK(!matcher.Match("abc", CommandLineFlagMatcher::kNoArgument));
}

}  // namespace
}  // namespace silifuzz

// ========================================================================= //

NOLIBC_TEST_MAIN({
  RUN_TEST(FlagMatcher, Constructor);
  RUN_TEST(FlagMatcher, ConstructorNonConstPointers);
  RUN_TEST(FlagMatcher, FlagWithoutArgument);
  RUN_TEST(FlagMatcher, FlagWithFollowingArgument);
  RUN_TEST(FlagMatcher, FlagWithEmbeddedArgument);
  RUN_TEST(FlagMatcher, FlagWithEmptyArgument);
  RUN_TEST(FlagMatcher, EndOfCommandLine);
})
