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

#include "./util/crc32c_internal.h"

namespace silifuzz {

// ---------- Implementation details ----------

namespace internal {

// To zero-extend a CRC32C value by 'n' zeros, we use extension tables for
// powers of 2. We do a zero-extension for each set bit in n. To overall
// extension is done with O(log n) power-of-2 zero extension.
inline constexpr size_t kNumCRC32CZeroExtensionTables =
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
