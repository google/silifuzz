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

#include "./util/atoi_internal.h"

#include <cstddef>
#include <limits>

namespace silifuzz {
namespace atoi_internal {

int DigitValue(int base, char c) {
  int value;
  if (c >= '0' && c <= '9') {
    value = c - '0';
  } else if (c >= 'a' && c <= 'z') {
    value = c - 'a' + 10;
  } else if (c >= 'A' && c <= 'Z') {
    value = c - 'A' + 10;
  } else {
    return -1;
  }
  return value < base ? value : -1;
}

bool StrToU64(int base, const char* str, size_t len, uint64_t* result) {
  uint64_t value = 0;
  if (*str == '\0') {  // 'str' cannot be empty.
    return false;
  }

  // limit_value * base + limit_digit = max().
  const uint64_t limit_value = std::numeric_limits<uint64_t>::max() / base;
  const uint64_t limit_digit = std::numeric_limits<uint64_t>::max() % base;

  for (size_t i = 0; i < len && str[i] != '\0'; ++i) {
    const int digit = DigitValue(base, str[i]);
    if (digit < 0) {
      return false;
    }

    // Check for overflow.
    if (value > limit_value || (value == limit_value && digit > limit_digit)) {
      return false;
    }
    value = value * base + digit;
  }

  *result = value;
  return true;
}

}  // namespace atoi_internal
}  // namespace silifuzz
