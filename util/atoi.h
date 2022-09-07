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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_ATOI_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_ATOI_H_

#include <cstddef>
#include <cstdint>

namespace silifuzz {

// Converts a decimal number represented by 'str' and stores converted value
// in *'result'. 'str' must be a non-empty C string consisting only of decimal
// digits. The converted value must also be representable by uint64_t type.
// Returns true iff conversion is successful.
bool DecToU64(const char* str, uint64_t* result);

// Like the above but converts up to the first 'len' characters of 'str'.
// If str terminates before 'len', the conversion is up the string length.
// This works similar to strncpy() and strncmp().
bool DecToU64(const char* str, size_t len, uint64_t* result);

// Like DecToU64() above but for hexadecimal numbers. 'str' may have an prefix
// '0x' or '0X'.  Except for the prefix, it must consist entirely of hexadecimal
// digits in either upper or lower case.
bool HexToU64(const char* str, uint64_t* result);

// Like the above but converts up to the first 'len' characters of 'str'.
bool HexToU64(const char* str, size_t len, uint64_t* result);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_ATOI_H_
