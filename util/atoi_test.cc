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

#include "./util/atoi.h"

#include <limits>

#include "./util/atoi_internal.h"
#include "./util/checks.h"
#include "./util/itoa.h"
#include "./util/nolibc_gunit.h"

// ========================================================================= //

namespace silifuzz {
namespace {

TEST(AtoiInternal, DigitValue) {
  // Check decimal digits.
  constexpr char kDecDigits[11] = "0123456789";
  for (int i = 0; i < 10; ++i) {
    CHECK_EQ(atoi_internal::DigitValue(10, kDecDigits[i]), i);
  }

  // Check boundary values.
  CHECK_EQ(atoi_internal::DigitValue(10, '0' - 1), -1);
  CHECK_EQ(atoi_internal::DigitValue(10, '9' + 1), -1);

  // Check hexadecimal digits
  constexpr char kLowerCaseHexDigits[17] = "0123456789abcdef";
  constexpr char kUpperCaseHexDigits[17] = "0123456789ABCDEF";
  for (int i = 0; i < 16; ++i) {
    CHECK_EQ(atoi_internal::DigitValue(16, kLowerCaseHexDigits[i]), i);
    CHECK_EQ(atoi_internal::DigitValue(16, kUpperCaseHexDigits[i]), i);
  }

  // Check boundary values.
  CHECK_EQ(atoi_internal::DigitValue(16, '0' - 1), -1);
  CHECK_EQ(atoi_internal::DigitValue(16, '9' + 1), -1);
  CHECK_EQ(atoi_internal::DigitValue(16, 'a' - 1), -1);
  CHECK_EQ(atoi_internal::DigitValue(16, 'A' - 1), -1);
  CHECK_EQ(atoi_internal::DigitValue(16, 'f' + 1), -1);
  CHECK_EQ(atoi_internal::DigitValue(16, 'F' + 1), -1);
}

TEST(Atoi, DecToU64) {
  uint64_t value;

  // Check illegal inputs
  CHECK(!DecToU64("", &value));
  CHECK(!DecToU64("a", &value));
  CHECK(!DecToU64("0!", &value));
  CHECK(!DecToU64("18446744073709551616", &value));

  // Check limits
  CHECK(DecToU64("0", &value));
  CHECK_EQ(value, 0);
  CHECK(DecToU64("18446744073709551615", &value));
  CHECK_EQ(18446744073709551615ULL, value);

  // Check IntStr->DecToU64.  Test up to bit 62 as IntStr takes signed
  // input. The powers of 2 produce input of varying lengths and digits.
  for (int i = 0; i < 63; ++i) {
    uint64_t expected = static_cast<uint64_t>(1) << i;
    CHECK(DecToU64(IntStr(expected), &value));
    CHECK_EQ(value, expected);
  }
}

TEST(Atoi, DecToU64WithLength) {
  uint64_t value;
  CHECK(!DecToU64("42!", 3, &value));
  CHECK(DecToU64("42", 2, &value));
  CHECK_EQ(value, 42);

  // Check early termination.
  CHECK(DecToU64("112358", 1000, &value));
  CHECK_EQ(value, 112358);
  CHECK(DecToU64("1230000000000000000000000000000000000000000", 3, &value));
  CHECK_EQ(value, 123);
}

TEST(Atoi, HexToU64) {
  uint64_t value;
  CHECK(!HexToU64("", &value));
  CHECK(!HexToU64("g", &value));
  CHECK(!HexToU64("0!", &value));
  CHECK(!HexToU64("10000000000000000", &value));

  // Check limits
  CHECK(HexToU64("0", &value));
  CHECK_EQ(value, 0);
  CHECK(HexToU64("0Xffffffffffffffff", &value));  // also test '0X' prefix.
  CHECK_EQ(0xffffffffffffffffULL, value);

  // Check HexStr->HexToU64. Test up to 10^19.
  // The powers of 10 produce input of varying lengths and hex digits.
  uint64_t expected = 1;
  for (int i = 0; i < 19; ++i, expected *= 10) {
    // Check hex number with prefix.
    CHECK(HexToU64(HexStr(expected), &value));
    CHECK_EQ(value, expected);

    // Skip '0x' prefix.
    CHECK(HexToU64(HexStr(expected) + 2, &value));
    CHECK_EQ(value, expected);
  }

  // Check upper and lower cases.
  CHECK(HexToU64("abcdefABCDEF", &value));
  CHECK_EQ(value, 0xabcdefabcdef);
}

TEST(Atoi, HexToU64WithLength) {
  uint64_t value;
  CHECK(!HexToU64("0x2a!", 5, &value));
  CHECK(HexToU64("0x2a!", 4, &value));
  CHECK_EQ(value, 42);

  // Check early termination.
  CHECK(HexToU64("0xabc", 1000, &value));
  CHECK_EQ(value, 0xabc);
  CHECK(HexToU64("0x1230000000000000000000000000000000000000000", 5, &value));
  CHECK_EQ(value, 0x123);
}

}  // namespace
}  // namespace silifuzz

// ========================================================================= //

NOLIBC_TEST_MAIN({
  RUN_TEST(AtoiInternal, DigitValue);
  RUN_TEST(Atoi, DecToU64);
  RUN_TEST(Atoi, DecToU64WithLength);
  RUN_TEST(Atoi, HexToU64);
  RUN_TEST(Atoi, HexToU64WithLength);
})
