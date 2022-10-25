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

#include "./util/testing/status_macros.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/statusor.h"

namespace silifuzz::testing {
namespace {

TEST(StatusMacrosTest, AssertOkAndAssign) {
  absl::StatusOr<std::string> sor_message("Hello, world");
  ASSERT_OK_AND_ASSIGN(std::string message, sor_message);
  EXPECT_EQ(message, "Hello, world");

  absl::StatusOr<int> sor_value(777);
  ASSERT_OK_AND_ASSIGN(int value, sor_value);
  EXPECT_EQ(value, 777);
}

TEST(StatusMacrosTest, AssertOk) {
  absl::Status status = absl::OkStatus();
  ASSERT_OK(status);

  absl::StatusOr<std::string> sor_message("Hello, world");
  ASSERT_OK(sor_message);
}

TEST(StatusMacrosTest, ExpectOk) {
  absl::Status status = absl::OkStatus();
  EXPECT_OK(status);

  absl::StatusOr<std::string> sor_message("Hello, world");
  EXPECT_OK(sor_message);
}

}  // namespace
}  // namespace silifuzz::testing
