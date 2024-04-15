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

// CRC-32C library.
// This computes checksum of a block of uint8_t into a 32-bit CRC value using
// CRC-32C algorithm, which is hardware accelerated on both x86_64 and aarch64.
// This library uses hardware acceleration whenever possible. Otherwise it falls
// back to a software implementation based on table look-up. The table is
// generated using public domain software described in "A Painless Guide To CRC
// Error Detection Algorithms" (https://zlib.net/crc_v3.txt)

#include "./util/crc32c.h"

#include <cstddef>
#include <cstdint>

#include "./util/crc32c_internal.h"

#ifdef __aarch64__
#include <sys/auxv.h>
#endif
#include <algorithm>
#include <atomic>

#include "./util/cpu_features.h"

// On x86, we want to generate CRC32C instructions in SSE 4.2 regardless of
// target setting of the compiler.
#ifdef __x86_64__
#define SSE4_2_TARGET_ATTRIBUTE __attribute__((target("sse4.2")))
#else
#define SSE4_2_TARGET_ATTRIBUTE  // NOP on non-x86.
#endif

namespace silifuzz {

namespace internal {

namespace {

// Compute CRC32C using hardware acceleration. This is optimized for the
// case when both 'data' and 'n' are 64-bit aligned.
template <typename CRC32CFunctions>
// We need to add target attribute in crc32c_accelerated_impl on the x86 or
// else methods in X86CRC32CFunctions will not be inlined. This is fine as the
// accelerated implementation is only called if SSE 4.2 is reported in CPUID.
SSE4_2_TARGET_ATTRIBUTE uint32_t crc32c_accelerated_impl(uint32_t seed,
                                                         const uint8_t* data,
                                                         size_t n) {
  uint32_t value = seed ^ 0xffffffffU;

  // Align input to 64-bit boundary.
  const size_t offset_in_qword =
      reinterpret_cast<uintptr_t>(data) % sizeof(uint64_t);
  if (offset_in_qword != 0) {
    const size_t bytes = std::min<size_t>(n, 8 - offset_in_qword);
    for (size_t i = 0; i < bytes; i++) {
      value = CRC32CFunctions::crc32c_uint8(value, data[i]);
    }
    n -= bytes;
    data += bytes;
  }

  // For sufficiently large block, it is better to split input into multiple
  // streams to hidden the latency of CRC instruction. For many x86
  // architectures the latency is 3 cycles. We expect something similar for
  // ARM. While splitting input can hide instruction latency, combining the
  // partial results is very costly for us. There are carryless multiply
  // instructions on both X86 (see CLMUL extension) and ARM to make combination
  // more efficient but on the x86 those instructions are vector instructions
  // so we want to avoid using them to reduce perturbation to the vector state.
  const size_t kBigBlockSize = 512;
  if (n >= kBigBlockSize) {
    constexpr size_t kNumStreams = 3;
    size_t block_size = n / sizeof(uint64_t) / kNumStreams;
    size_t block_byte_size = block_size * sizeof(uint64_t);
    uint32_t value2 = 0, value3 = 0;

    const uint64_t* u64_data = reinterpret_cast<const uint64_t*>(data);
    const uint64_t* u64_data_2 =
        reinterpret_cast<const uint64_t*>(data + block_byte_size);
    const uint64_t* u64_data_3 =
        reinterpret_cast<const uint64_t*>(data + block_byte_size * 2);

    // Compute kNumStreams CRC values simultaneously to hide latency of CRC
    // instruction.
    for (size_t i = 0; i < block_size; ++i) {
      value = CRC32CFunctions::crc32c_uint64(value, u64_data[i]);
      value2 = CRC32CFunctions::crc32c_uint64(value2, u64_data_2[i]);
      value3 = CRC32CFunctions::crc32c_uint64(value3, u64_data_3[i]);
    }

    // Combine multiple CRC values into one. For two byte strings M1 and M2,
    // CRC(M1 ^ M2) = CRC(M1) ^ CRC(M2). For the byte string M1.M2 formed by
    // concatenating M1 and M2,
    //    CRC(M1.M2) = CRC(M1.ZEROS(LEN(M2)) ^ M2)
    //               = CRC(M1.ZEROS(LEN(M2))) ^ CRC(M2)
    // where ZEROS(n) is a strings of n zero bytes.
    value = internal::crc32c_zero_extend(value, block_byte_size);
    value ^= value2;
    value = internal::crc32c_zero_extend(value, block_byte_size);
    value ^= value3;

    // Advance data pointer.
    n -= block_byte_size * kNumStreams;
    data += block_byte_size * kNumStreams;
  }

  while (n >= sizeof(uint64_t)) {
    value = CRC32CFunctions::crc32c_uint64(
        value, *reinterpret_cast<const uint64_t*>(data));
    n -= sizeof(uint64_t);
    data += sizeof(uint64_t);
  }

  // Process tail of input one byte at a time.
  for (size_t i = 0; i < n; ++i) {
    value = CRC32CFunctions::crc32c_uint8(value, data[i]);
  }

  return value ^ 0xffffffffU;
}

#ifdef __x86_64__
struct X86CRC32CFunctions {
  SSE4_2_TARGET_ATTRIBUTE static inline uint32_t crc32c_uint8(uint32_t crc,
                                                              uint8_t value) {
    return __builtin_ia32_crc32qi(crc, value);
  }
  SSE4_2_TARGET_ATTRIBUTE static inline uint32_t crc32c_uint64(uint32_t crc,
                                                               uint64_t value) {
    return __builtin_ia32_crc32di(crc, value);
  }
};
#endif

#ifdef __aarch64__
struct ARMCRC32CFunctions {
  static inline uint32_t crc32c_uint8(uint32_t crc, uint8_t value) {
    return __builtin_arm_crc32cb(crc, value);
  }
  static inline uint32_t crc32c_uint64(uint32_t crc, uint64_t value) {
    return __builtin_arm_crc32cd(crc, value);
  }
};
#endif

#if defined(__aarch64__)
uint32_t crc32c_accelerated(uint32_t seed, const uint8_t* data, size_t n) {
  return crc32c_accelerated_impl<ARMCRC32CFunctions>(seed, data, n);
}
#elif defined(__x86_64__)
uint32_t crc32c_accelerated(uint32_t seed, const uint8_t* data, size_t n) {
  return crc32c_accelerated_impl<X86CRC32CFunctions>(seed, data, n);
}
#else
uint32_t crc32c_accelerated(uint32_t seed, const uint8_t* data, size_t n) {
  return crc32c_unaccelerated(seed, data, n);
}
#endif

// Tells if CRC32C acceleration is available at runtime.
bool has_crc32c_accelerated() {
#if defined(__x86_64__)
  return HasX86CPUFeature(X86CPUFeatures::kSSE4_2);
#elif defined(__aarch64__)
  return (getauxval(AT_HWCAP) & HWCAP_CRC32) != 0;
#else
  return false;
#endif
}

// Initializes best_crc32c_impl upon the first call to crc32c.
uint32_t crc32c_init(uint32_t seed, const uint8_t* data, size_t n) {
  crc32c_function_ptr impl =
      has_crc32c_accelerated() ? &crc32c_accelerated : &crc32c_unaccelerated;
  // Use exchange instead of store in case we tsan in the future.
  best_crc32c_impl.exchange(impl);
  return (*impl)(seed, data, n);
}

}  // namespace

// Pointer to the best CRC-32C implementation we can use at run-time.
// Initially it points to crc32c_init.
std::atomic<crc32c_function_ptr> best_crc32c_impl =
    ATOMIC_VAR_INIT(&crc32c_init);

uint32_t crc32c_zero_extend(uint32_t crc, size_t n) {
  // TODO(dougkwan): Precompute zero extension tables for the most frequently
  // occurring values of 'n' so that we only do extension once instead of
  // O(log n) times. We probably want to precompute for CRC block sizes 2048 and
  // 4096, which needs tables for sizes 680 and 1360 respectively.
  for (size_t i = 0; n != 0 && i < kNumCRC32CZeroExtensionTables; ++i) {
    size_t bit = static_cast<size_t>(1) << i;
    if ((n & bit) != 0) {
      crc = internal::GetCRC32CZeroExtensionTableForBit(i).Extend(crc);
      n &= ~bit;
    }
  }
  return crc;
}

}  // namespace internal

}  // namespace silifuzz
