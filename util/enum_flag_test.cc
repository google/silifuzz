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

#include "./util/enum_flag.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "./util/itoa.h"
#include "./util/testing/status_matchers.h"

namespace silifuzz {

enum TestEnum { kFirst, kSecond };

template <>
constexpr const char* EnumNameMap<TestEnum>[2] = {"first-option",
                                                  "second-option"};

namespace {

using silifuzz::testing::IsOkAndHolds;
using silifuzz::testing::StatusIs;
using ::testing::HasSubstr;

TEST(EnumFlag, ParseEnum) {
  ASSERT_THAT(ParseEnum<TestEnum>("first-option"), IsOkAndHolds(kFirst));
  ASSERT_THAT(ParseEnum<TestEnum>("second-option"), IsOkAndHolds(kSecond));
  ASSERT_THAT(ParseEnum<TestEnum>("no-option"),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Want one of: first-option, second-option")));
}

}  // namespace
}  // namespace silifuzz
