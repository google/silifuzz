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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_NOLIBC_GUNIT_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_NOLIBC_GUNIT_H_
// Utilities for building no libc gunit test.

#if defined(SILIFUZZ_BUILD_FOR_NOLIBC)

// Quick substitution for gunit parts.
#define TEST(Class, Name) void Class##_##Name()

#define RUN_TEST(Class, Name)                   \
  {                                             \
    LOG_INFO("[ RUN      ] " #Class "." #Name); \
    silifuzz::Class##_##Name();                 \
    LOG_INFO("[       OK ] " #Class "." #Name); \
  }
#define EXPECT_DEATH_IF_SUPPORTED(code, matcher) /* unsupported */

// Runs tests under the nolibc environment.  This is intended to be used to
// implement the main() function of a unit test.  'run_tests' is normally a
// sequence of RUN_TEST() calls -- see above.  The macro expands into a full
// main() function that executes 'run_tests' and then exits main().
#define NOLIBC_TEST_MAIN(run_tests) \
  int main() {                      \
    {run_tests};                    \
    LOG_INFO("[  PASSED  ]");       \
    return 0;                       \
  }

#define GTEST_SKIP()        \
  LOG_INFO("Test skipped"); \
  return;

#else  // defined(SILIFUZZ_BUILD_FOR_NOLIBC)

#define NOLIBC_TEST_MAIN(run_tests)

// include normal gunit.h if we are using regular libc
#include "gtest/gtest.h"

#endif  // defined(SILIFUZZ_BUILD_FOR_NOLIBC)

#define EXPECT_STR_EQ(got, want)                        \
  do {                                                  \
    if (strcmp(got, want) != 0) {                       \
      LOG_FATAL("got: [", got, "] want: [", want, "]"); \
    }                                                   \
  } while (0);

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_NOLIBC_GUNIT_H_
