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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_MISC_UTIL_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_MISC_UTIL_H_

// This library contains various simple utilities that do not yet deserve
// a bigger library with a proper name. Move things if that happens.

#include <cstdint>      // for uintptr_t
#include <type_traits>  // for std::enable_if_t, std::is_enum

namespace silifuzz {

// A convenient enum->int converter. Useful for "enum class" enums that
// do not auto-convert to int, e.g. for CHECK_EQ() and logging.
template <class T, std::enable_if_t<std::is_enum<T>::value, int> = 0>
inline constexpr int ToInt(const T& x) {
  return static_cast<int>(x);
}

// Maps uintptr_t to void*.
inline void* AsPtr(uintptr_t addr) { return reinterpret_cast<void*>(addr); }

// Maps void* to uintptr_t.
inline uintptr_t AsInt(const void* ptr) {
  return reinterpret_cast<uintptr_t>(ptr);
}

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_MISC_UTIL_H_
