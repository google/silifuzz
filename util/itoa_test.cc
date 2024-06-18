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

#include "./util/itoa.h"

#include <csignal>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/attributes.h"

namespace silifuzz {

enum class MyEnum {
  kA = 0,
  kB,
  // kC,
  kD = 3,
  kE,
  kF = -10,
};

// Exercise .h's recommendation for separate declaration and definition of
// a EnumNameMap's specialization.
template <>
extern const char* EnumNameMap<MyEnum>[4];

// ========================================================================= //

namespace {

TEST(IntStr, All) {
  // Small:
  EXPECT_STREQ(IntStr(0), "0");
  EXPECT_STREQ(IntStr(1), "1");
  EXPECT_STREQ(IntStr(-2), "-2");
  EXPECT_STREQ(IntStr(42), "42");
  EXPECT_STREQ(IntStr(-4242), "-4242");
  // Near-max:
  EXPECT_STREQ(IntStr(9223372036854775805LL), "9223372036854775805");
  EXPECT_STREQ(IntStr(-9223372036854775806LL), "-9223372036854775806");
  // Max:
  EXPECT_STREQ(IntStr(9223372036854775807LL), "9223372036854775807");
  EXPECT_STREQ(IntStr(-9223372036854775807LL - 1), "-9223372036854775808");
}

TEST(ErrnoStr, All) {
  EXPECT_STREQ(ErrnoStr(1), "errno=1");
  EXPECT_STREQ(ErrnoStr(-2147483647), "errno=-2147483647");
}

TEST(HexStr, All) {
  // Small:
  EXPECT_STREQ(HexStr(0), "0x0");
  EXPECT_STREQ(HexStr(10), "0xa");
  EXPECT_STREQ(HexStr(0x42), "0x42");
  // Near-max:
  EXPECT_STREQ(HexStr(((__uint128_t)0xFFFFFFFFFFFFFFFFULL) << 64 |
                      0xFFFFFFFFFFFFFFFAULL),
               "0xfffffffffffffffffffffffffffffffa");
  // Max:
  EXPECT_STREQ(HexStr(((__uint128_t)0xFFFFFFFFFFFFFFFFULL) << 64 |
                      0xFFFFFFFFFFFFFFFFULL),
               "0xffffffffffffffffffffffffffffffff");
  EXPECT_STREQ(HexStr(-1), "0xffffffffffffffffffffffffffffffff");

  // Ptr:
  int x;
  EXPECT_THAT(HexStr(&x), ::testing::MatchesRegex("0x[0-9a-f]+"));
}

TEST(BoolStr, All) {
  EXPECT_STREQ(BoolStr(true), "true");
  EXPECT_STREQ(BoolStr(false), "false");
}

enum FooEnum { kFoo = 0 };

TEST(EnumStr, All) {
  EXPECT_STREQ(EnumStr(MyEnum::kA), "kA");
  EXPECT_STREQ(EnumStr(MyEnum::kB), "kB");
  EXPECT_STREQ(EnumStr(MyEnum::kD), "kD-name");

  auto missing_kC = static_cast<MyEnum>(2);
  EXPECT_STREQ(EnumStr(missing_kC), "NO-ENUM-NAME-DEFINED");
  EXPECT_STREQ(EnumStr(MyEnum::kE), "NO-ENUM-NAME-DEFINED");
  EXPECT_STREQ(EnumStr(MyEnum::kF), "NO-ENUM-NAME-DEFINED");

  EXPECT_STREQ(EnumStr(kFoo), "NO-ENUM-NAME-DEFINED");
}

TEST(SignalNameStr, All) {
  EXPECT_STREQ(SignalNameStr(SIGHUP), "SIGHUP");
  EXPECT_STREQ(SignalNameStr(SIGSEGV), "SIGSEGV");
  EXPECT_STREQ(SignalNameStr(SIGILL), "SIGILL");
  EXPECT_STREQ(SignalNameStr(SIGABRT), "SIGABRT");
  EXPECT_STREQ(SignalNameStr(SIGFPE), "SIGFPE");
  EXPECT_STREQ(SignalNameStr(SIGKILL), "SIGKILL");
  EXPECT_STREQ(SignalNameStr(SIGUSR1), "SIGUSR1");
  EXPECT_STREQ(SignalNameStr(__SIGRTMIN + 18), "__SIGRTMIN+18");
}

}  // namespace

template <>
ABSL_CONST_INIT const char* EnumNameMap<MyEnum>[4] = {"kA", "kB", nullptr,
                                                      "kD-name"};

}  // namespace silifuzz
