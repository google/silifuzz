// Copyright 2023 The SiliFuzz Authors.
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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_PAGE_UTIL_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_PAGE_UTIL_H_

#include <cstddef>
#include <cstdint>

#include "./util/checks.h"

namespace silifuzz {

constexpr size_t kPageSize = 0x1000;

constexpr bool IsPageAligned(uintptr_t value, uintptr_t page_size = kPageSize) {
  return (value & (page_size - 1)) == 0;
}

inline bool IsPageAligned(const void* ptr, uintptr_t page_size = kPageSize) {
  return IsPageAligned(reinterpret_cast<uintptr_t>(ptr), page_size);
}

constexpr uintptr_t RoundDownToPageAlignment(uintptr_t value,
                                             uintptr_t page_size = kPageSize) {
  return value & ~(page_size - 1);
}

template <typename T>
T* RoundDownToPageAlignment(T* ptr, uintptr_t page_size = kPageSize) {
  return reinterpret_cast<T*>(
      RoundDownToPageAlignment(reinterpret_cast<uintptr_t>(ptr), page_size));
}

// Not constexpr because of CHECK
inline uintptr_t RoundUpToPageAlignment(uintptr_t value,
                                        uintptr_t page_size = kPageSize) {
  uintptr_t tmp = 0;
  // TODO(ncbray): propagate error
  CHECK(!__builtin_add_overflow(value, page_size - 1, &tmp));
  return tmp & ~(page_size - 1);
}

template <typename T>
T* RoundUpToPageAlignment(T* ptr, uintptr_t page_size = kPageSize) {
  return reinterpret_cast<T*>(
      RoundUpToPageAlignment(reinterpret_cast<uintptr_t>(ptr), page_size));
}

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_PAGE_UTIL_H_
