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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_CRC32C_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_CRC32C_H_
#include <atomic>
#include <climits>
#include <cstddef>
#include <cstdint>

namespace silifuzz {

// ---------- Implementation details ----------

namespace internal {

// We want to combine CRC values of different parts of an input into a
// single value as if all the parts were processed together as one unit.
// In order to do this, we want to compute a new CRC value from an existing
// one that we would get by appending a number of zero bytes at the end.
// This zero extension operation is equivalent to doing a matrix multiplication
// in the GF(2) finite field. For CRC32C, we can use a 32x32 matrix stored as
// an array of 32 uint32_t values. To further speed up computation, we treat
// divide a CRC32C values into groups of 4 bits and use a look up table for
// each group. This uses 4 times more memory than using a 32x32 bit matrix but
// is faster.
//
// This must of a POD struct as we precompute extension tables and store them
// in source code.
struct CRC32CZeroExtensionTable {
  static constexpr size_t kBitsPerGroup = 4;  // must divide 32.
  static_assert(32 % kBitsPerGroup == 0);
  static constexpr size_t kNumGroups = 32 / kBitsPerGroup;
  static constexpr size_t kGroupTableSize = 1 << kBitsPerGroup;

  // Extends a CRC32C value by appending zero bytes at the end.
  // Note: this operates on non-negated CRC32C values because h/w CRC32C
  // instructions do not negate the input and output values.
  uint32_t Extend(uint32_t crc) const;

  // Returns a CRC32CZeroExtensionTable that does not perform zero extension.
  // Zero().Extend() is a nop.
  static CRC32CZeroExtensionTable Zero();

  // Returns a CRC32CZeroExtensionTable that does a single-byte zero extension.
  static CRC32CZeroExtensionTable One();

  // Returns a CRC32CZeroExtensionTable that performs that same extensions
  // performed by 'a' and then 'b'.
  // REQUIRES: a.n + b.n must be representable by size_t.
  static CRC32CZeroExtensionTable Add(const CRC32CZeroExtensionTable& a,
                                      const CRC32CZeroExtensionTable& b);

  size_t n;  // number of zero bytes appended to a CRC32C value.
  uint32_t table[kNumGroups][kGroupTableSize];
};

// To zero-extend a CRC32C value by 'n' zeros, we use extension tables for
// powers of 2. We do a zero-extension for each set bit in n. To overall
// extension is done with O(log n) power-of-2 zero extension.
static constexpr size_t kNumCRC32CZeroExtensionTables =
    sizeof(size_t) * CHAR_BIT;

// Returns the CRC32C zero extension table for a given bit.
//
// TODO(dougkwan): Make the tables accessible without calling this helper.
// The tables are in a separate file than crc32c.cc. On the x86, the linker
// does not correctly resolve data relocation to the tables, causing the
// binary to crash. This may be related to using R_X86_64_REX_GOTPCRELX
// relocation in a static binary but we have not root caused it yet.
// This helper is in the same file as the tables so it works.
const CRC32CZeroExtensionTable& GetCRC32CZeroExtensionTableForBit(size_t i);

using crc32c_function_ptr = uint32_t (*)(uint32_t, const uint8_t*, size_t);

// Function pointer for the best CRC32C implementation.  This is set to
// a real CRC32C implementation at the first call.  We cannot use ifunc here
// as code can be used in both nolibc and google3 environments.
extern std::atomic<crc32c_function_ptr> best_crc32c_impl;

// Computes CRC32C without using any hardware acceleration.
// This should works on any platform. This is exposed for testing.
uint32_t crc32c_unaccelerated(uint32_t seed, const uint8_t* data, size_t n);

// Internal version of crc3c_zero_extend() below that does not negate the
// input and output bits.
uint32_t crc32c_zero_extend(uint32_t crc, size_t n);

}  // namespace internal

// --------- Public interface ----------

// Computes CRC32C checksum of 'n' bytes at 'data' using 'seed'.
// This may use hardware acceleration if available.
inline uint32_t crc32c(uint32_t seed, const uint8_t* data, size_t n) {
  return (*internal::best_crc32c_impl.load(std::memory_order_relaxed))(seed,
                                                                       data, n);
}

// Computes a new CRC32C checksum of what we would get by appending
// 'n' zero bytes to the original input from which 'crc' was computed.
inline uint32_t crc32c_zero_extend(uint32_t crc, size_t n) {
  return internal::crc32c_zero_extend(crc ^ 0xffffffffUL, n) ^ 0xffffffffUL;
}

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_CRC32C_H_
