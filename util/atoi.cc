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

namespace silifuzz {

bool DecToU64(const char* str, size_t len, uint64_t* result) {
  return atoi_internal::StrToU64(10, str, len, result);
}

bool DecToU64(const char* str, uint64_t* result) {
  return DecToU64(str, std::numeric_limits<size_t>::max(), result);
}

// Like DecToU64() above but for hexadecimal numbers.
bool HexToU64(const char* str, size_t len, uint64_t* result) {
  // Skip optional prefix. 0x/0X
  if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
    str += 2;
    len -= 2;
  }
  return atoi_internal::StrToU64(16, str, len, result);
}

// Like DecToU64() above but for hexadecimal numbers.
bool HexToU64(const char* str, uint64_t* result) {
  return HexToU64(str, std::numeric_limits<size_t>::max(), result);
}

}  // namespace silifuzz
