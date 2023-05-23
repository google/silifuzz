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
#include <cstddef>
#include <cstdint>

namespace silifuzz {

// ---------- Implementation details ----------

namespace internal {

using crc32c_function_ptr = uint32_t (*)(uint32_t, const uint8_t*, size_t);

// Function pointer for the best CRC32C implementation.  This is set to
// a real CRC32C implementation at the first call.  We cannot use ifunc here
// as code can be used in both nolibc and google3 environments.
extern std::atomic<crc32c_function_ptr> best_crc32c_impl;

// Computes CRC32C without using any hardware acceleration.
// This should works on any platform. This is exposed for testing.
uint32_t crc32c_unaccelerated(uint32_t seed, const uint8_t* data, size_t n);
}  // namespace internal

// --------- Public interface ----------

// Computes CRC32C checksum of 'n' bytes at 'data' using 'seed'.
// This may use hardware acceleration if available.
inline uint32_t crc32c(uint32_t seed, const uint8_t* data, size_t n) {
  return (*internal::best_crc32c_impl.load(std::memory_order_relaxed))(seed,
                                                                       data, n);
}

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_CRC32C_H_
