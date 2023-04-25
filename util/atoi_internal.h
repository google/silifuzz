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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_ATOI_INTERNAL_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_ATOI_INTERNAL_H_

// Internal header for atoi.cc.
// This should only be included by atoi.cc and atoi_test.cc.

#include <stddef.h>

#include <cstdint>

#include "./util/checks.h"

namespace silifuzz {
namespace atoi_internal {

// Interprets character 'c' as a digit of the given 'base'.
// 'base' must be in [2,36], This characters '0'..'9' encode
// the numbers from 0 to 9. The characters 'a'..'z' and 'A'..'Z'
// both encode the numbers 10 to 36, i.e. case does not matter.
// This corresponds to the digit encoding used in strtol().
// If 'c' is a valid digit in 'base', returns converted value.
// Otherwise returns -1.
int DigitValue(int base, char c);

// Converts 'str' into a uint64_t using 'base'.  'str' must be non-empty
// and contain up to at most 'len' characters that can be interpreted as digits
// in 'base'. The converted value must not overflow uint64_t. Returns true if
// conversion is successful and puts value in *'result'.  Otherwise returns
// false.
bool StrToU64(int base, const char* str, size_t len, uint64_t* result);

}  // namespace atoi_internal
}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_ATOI_INTERNAL_H_
