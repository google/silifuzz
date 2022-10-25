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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_TESTING_STATUS_MACROS_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_TESTING_STATUS_MACROS_H_

#include "absl/status/statusor.h"
#include "./util/testing/status_matchers.h"

namespace silifuzz::testing {

// ===============================
// ASSERT_OK_AND_ASSIGN(dest, src)
// ===============================
//
// Macro that evaluates src as a StatusOr, asserts that the status is OK, and
// assigns the value to dest.
//
// Example:
//   ...
//   StatusOr<std::string> sor_message("Hello, world");
//   ASSERT_OK_AND_ASSIGN(std::string message, sor_message);
//   EXPECT_EQ(message, "Hello, world");
//
// Note: Uses of ASSERT_OK_AND_ASSIGN in single-statement if blocks without
// curly braces is not valid due to the expansion into a multi-statement macro.
// The macro body is not wrapped in a `do {} while (0)` to allow dest variables
// to be declared within the macro.

// Internal helper for concatenating macro values.
#define STATUS_MACROS_INTERNAL_CONCAT_IMPL_(x, y) x##y
#define STATUS_MACROS_INTERNAL_CONCAT_(x, y) \
  STATUS_MACROS_INTERNAL_CONCAT_IMPL_(x, y)

#undef ASSERT_OK_AND_ASSIGN
#undef ASSERT_OK_AND_ASSIGN_IMPL_
#define ASSERT_OK_AND_ASSIGN(dest, src) \
  ASSERT_OK_AND_ASSIGN_IMPL_(           \
      STATUS_MACROS_INTERNAL_CONCAT_(status_or_, __LINE__), dest, src)
#define ASSERT_OK_AND_ASSIGN_IMPL_(status_or, dest, src) \
  auto status_or = (src);                                \
  ASSERT_THAT(status_or, silifuzz::testing::IsOk());     \
  dest = std::move(status_or).value();

// ===============
// ASSERT_OK(expr)
// ===============
//
// Macro that asserts that expr evaluates to an OK Status or StatusOr.
//
// ===============
// EXPECT_OK(expr)
// ===============
//
// Macro that expects that expr evaluates to an OK Status or StatusOr.

#undef ASSERT_OK
#define ASSERT_OK(expr) ASSERT_THAT(expr, silifuzz::testing::IsOk());

#undef EXPECT_OK
#define EXPECT_OK(expr) EXPECT_THAT(expr, silifuzz::testing::IsOk());

}  // namespace silifuzz::testing

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_TESTING_STATUS_MACROS_H_
