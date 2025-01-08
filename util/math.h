// Copyright 2025 The SiliFuzz Authors.
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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_MATH_UTIL_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_MATH_UTIL_H_

#include <type_traits>

#include "./util/checks.h"

namespace silifuzz {

template <typename T>
std::enable_if_t<std::is_integral_v<T>, T> RoundUpToPowerOfTwo(T value,
                                                               T target) {
  CHECK_GT(target, 0);
  CHECK_EQ_LOG(target & (target - 1), 0, "target must be a power of two");

  T tmp = 0;
  CHECK(!__builtin_add_overflow(value, target - 1, &tmp));
  return tmp & ~(target - 1);
}

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_MATH_UTIL_H_
