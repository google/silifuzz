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

#include <string.h>

#include <cstdint>
#include <limits>

namespace silifuzz {

namespace itoa_internal {

static const char kHexCharMap[] = "0123456789abcdef";

IntStr::IntStr(int64_t num) {
  // digits10 is the floor, we want ceil. +1 is a conservative approximation.
  constexpr auto max_digits = std::numeric_limits<decltype(num)>::digits10 + 1;
  static_assert(sizeof(rep_) >= max_digits + 2, "Increase size of rep_");
  ptr_ = rep_ + sizeof(rep_);
  *--ptr_ = '\0';
  bool is_neg = num < 0;
  // We do not do num = -num as it does not work for the abs-largest negative
  // int64.
  do {
    *--ptr_ = kHexCharMap[is_neg ? -(num % 10) : (num % 10)];
    num /= 10;
  } while (num != 0);
  if (is_neg) {
    *--ptr_ = '-';
  }
}

ErrnoStr::ErrnoStr(int num) : IntStr(num) {
  static constexpr char prefix[] = "errno=";
  constexpr size_t prefix_len = sizeof(prefix) - 1;
  // digits10 is the floor, we want ceil. +1 is a conservative approximation.
  constexpr auto max_digits = std::numeric_limits<decltype(num)>::digits10 + 1;
  static_assert(sizeof(rep_) >= prefix_len + max_digits + 2,
                "Increase size of rep_");
  // The IntStr constructor should have turned the integer into a string, now
  // prepend a prefix.
  ptr_ -= prefix_len;
  memcpy(ptr_, prefix, prefix_len);
}

// ========================================================================= //

// Impl is borrowed from absl::substitute_internal::Arg::Arg(const void* value).
HexStr::HexStr(__uint128_t num) {
  static_assert(sizeof(rep_) >= sizeof(num) * 2 + 3, "Increase size of rep_");
  ptr_ = rep_ + sizeof(rep_);
  *--ptr_ = '\0';
  do {
    *--ptr_ = kHexCharMap[num & 0xf];
    num >>= 4;
  } while (num != 0);
  *--ptr_ = 'x';
  *--ptr_ = '0';
}

}  // namespace itoa_internal

// ========================================================================= //

const char* BoolStr(bool b) { return b ? "true" : "false"; }

}  // namespace silifuzz
