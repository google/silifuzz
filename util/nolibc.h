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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_NOLIBC_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_NOLIBC_H_

// This library (when built in the "nolibc" mode - see nolibc.bzl)
// provides header/inline declarations and definitions for the few utils
// from libc++ that are necessary to successfully build code for a basic binary
// without bringing in all of C++ runtime libs.
//
// Specifically: this library should be included:
// * Instead of <memory> when needing std::align() - use std_align() instead.
//
// See also nolibc_main.cc.

#if defined(SILIFUZZ_BUILD_FOR_NOLIBC)

#include <stdint.h>  // for uintptr_t
#include <cstddef>  // for std::size_t

// Provide an equivalent of std::align(); silifuzz code calls it.
namespace silifuzz {
inline void* std_align(std::size_t alignment, std::size_t size, void*& ptr,
                       std::size_t& space) {
  std::size_t rem = reinterpret_cast<uintptr_t>(ptr) % alignment;
  std::size_t shift = rem == 0 ? 0 : alignment - rem;
  if (size + shift > space) return nullptr;
  space -= shift;
  ptr = reinterpret_cast<char*>(ptr) + shift;
  return ptr;
}
}  // namespace silifuzz

#else  // !defined(SILIFUZZ_BUILD_FOR_NOLIBC)

#include <memory>  // for std::align()

namespace silifuzz {
inline void* std_align(std::size_t alignment, std::size_t size, void*& ptr,
                       std::size_t& space) {
  return std::align(alignment, size, ptr, space);
}
}  // namespace silifuzz

#endif  // !defined(SILIFUZZ_BUILD_FOR_NOLIBC)

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_NOLIBC_H_
