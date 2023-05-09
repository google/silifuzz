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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_UCONTEXT_UCONTEXT_BITOPS_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_UCONTEXT_UCONTEXT_BITOPS_H_

#include <cstdint>

#include "./util/ucontext/ucontext_types.h"

namespace silifuzz {

// Zero all the registers in the UContext.
// In practice, zeros the entire struct.
template <typename Arch>
void UContextClear(UContext<Arch>& result) {
  memset(&result, 0, sizeof(result));
}

// Counts the number of bits that have been set in all the registers.
// Assumes that struct padding of the input has been zeroed.
template <typename Arch>
size_t UContextPopCount(const UContext<Arch>& src) {
  static_assert(sizeof(UContext<Arch>) % sizeof(uint64_t) == 0);
  size_t count = 0;
  const uint64_t* src_ptr = reinterpret_cast<const uint64_t*>(&src);
  for (size_t i = 0; i < sizeof(UContext<Arch>) / sizeof(uint64_t); ++i) {
    count += __builtin_popcountll(src_ptr[i]);
  }
  return count;
}

// Create a bitmask in `result` that shows the bits that differ between `a` and
// `b`.
// Assumes that struct padding of the inputs has been zeroed.
template <typename Arch>
void UContextDiff(const UContext<Arch>& a, const UContext<Arch>& b,
                  UContext<Arch>& result) {
  static_assert(sizeof(UContext<Arch>) % sizeof(uint64_t) == 0);
  const uint64_t* a_ptr = reinterpret_cast<const uint64_t*>(&a);
  const uint64_t* b_ptr = reinterpret_cast<const uint64_t*>(&b);
  uint64_t* result_ptr = reinterpret_cast<uint64_t*>(&result);
  for (size_t i = 0; i < sizeof(UContext<Arch>) / sizeof(uint64_t); ++i) {
    result_ptr[i] = a_ptr[i] ^ b_ptr[i];
  }
}

// Compute which bits have changed between `a` and `b` as well as the direction
// of the change. If a bit is 0 in `a` and 1 in `b`, set that bit in `zero_one`.
// Similarly, if a bit is 1 in `a` and 0 in `b`, set that bit in `one_zero`. If
// a bit has not changed between a and b, do not modify the bit in the output
// structs. This function can be called multiple times with different (a, b)
// UContext pairs but the same (zero_one, one_zero) output pair to track if a
// bit has ever toggled throughout a sequence of register states. The output
// pair should be explicitly cleared before calling this function since this
// function will only ever set output bits and never clear them.
// Assumes that struct padding of the inputs has been zeroed.
template <typename Arch>
void UContextAccumulateToggle(const UContext<Arch>& a, const UContext<Arch>& b,
                              UContext<Arch>& zero_one,
                              UContext<Arch>& one_zero) {
  static_assert(sizeof(UContext<Arch>) % sizeof(uint64_t) == 0);
  const uint64_t* a_ptr = reinterpret_cast<const uint64_t*>(&a);
  const uint64_t* b_ptr = reinterpret_cast<const uint64_t*>(&b);
  uint64_t* zero_one_ptr = reinterpret_cast<uint64_t*>(&zero_one);
  uint64_t* one_zero_ptr = reinterpret_cast<uint64_t*>(&one_zero);

  for (size_t i = 0; i < sizeof(UContext<Arch>) / sizeof(uint64_t); ++i) {
    zero_one_ptr[i] |= ~a_ptr[i] & b_ptr[i];
    one_zero_ptr[i] |= a_ptr[i] & ~b_ptr[i];
  }
}

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_UCONTEXT_UCONTEXT_BITOPS_H_
