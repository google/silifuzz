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

#ifndef TESTING_SILIFUZZ_PROXIES_DSIM_BIT_STRUCT_H_
#define TESTING_SILIFUZZ_PROXIES_DSIM_BIT_STRUCT_H_

#include <cstddef>
#include <cstdint>

#include "absl/log/check.h"

namespace silifuzz::proxies {

// A bit struct that packs bit fields into a uint64_t.
class BitStruct {
 public:
  constexpr BitStruct() : BitStruct(0) {}
  explicit constexpr BitStruct(uint64_t bits) : bits_(bits) {}
  ~BitStruct() = default;

  // Copyable and movable by default.
  BitStruct(const BitStruct&) = default;
  BitStruct& operator=(const BitStruct&) = default;
  BitStruct(BitStruct&&) = default;
  BitStruct& operator=(BitStruct&&) = default;

  // Returns bit encoding of as uint64_t.
  uint64_t GetEncodedValue() const { return bits_; }

 protected:
  static inline constexpr uint64_t bit_mask(size_t n) {
    return (static_cast<uint64_t>(1) << n) - 1;
  }

  inline constexpr uint64_t get_bit_field(size_t shift, size_t width) const {
    return (bits_ >> shift) & bit_mask(width);
  }

  inline void constexpr set_bit_field(size_t shift, size_t width,
                                      uint64_t value) {
    const uint64_t mask = bit_mask(width);
    // Use DCHECK instead of CHECK so that this the function can
    // be evaluated in compile-time in a non-debug build.
    DCHECK_EQ(value & ~mask, 0);
    bits_ &= ~(mask << shift);
    bits_ |= (value & mask) << shift;
  }

 private:
  // Encoded form.
  uint64_t bits_;
};

// A macro for declaring fields in a bit struct.
#define SILIFUZZ_PROXY_BIT_STRUCT_FIELD(name, lsb, msb)           \
  static constexpr size_t k_##name##_shift = (lsb);               \
  static constexpr size_t k_##name##_width = ((msb) - (lsb) + 1); \
  static_assert(k_##name##_shift < 64);                           \
  static_assert(k_##name##_width > 0 && k_##name##_width <= 64);  \
  uint64_t name() const {                                         \
    return get_bit_field(k_##name##_shift, k_##name##_width);     \
  }                                                               \
  auto& set_##name(uint64_t value) {                              \
    set_bit_field(k_##name##_shift, k_##name##_width, value);     \
    return *this;                                                 \
  }

}  // namespace silifuzz::proxies

#endif  // TESTING_SILIFUZZ_PROXIES_DSIM_BIT_STRUCT_H_
