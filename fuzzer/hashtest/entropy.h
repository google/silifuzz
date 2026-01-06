// Copyright 2026 The Silifuzz Authors.
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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_ENTROPY_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_ENTROPY_H_

#include "absl/log/log.h"

namespace silifuzz {

// TODO(ncbray): should there be 8 GP entropy registers? The loop counter was
// carved out of the entropy pool, resulting in 7 registers.
// TODO(ncbray): should rbp be reserved as a frame pointer?
inline constexpr size_t kGPEntropyRegs = 7;
inline constexpr size_t kVecEntropyRegs = 8;
inline constexpr size_t kMaskEntropyRegs = 4;
inline constexpr size_t kMMXEntropyRegs = 4;

inline constexpr size_t kEntropyBytes512 =
    (kVecEntropyRegs * 512 + kMaskEntropyRegs * 64 + kGPEntropyRegs * 64 +
     kMMXEntropyRegs * 64) /
    8;

inline constexpr size_t kEntropyBytes256 =
    (kVecEntropyRegs * 256 + kGPEntropyRegs * 64 + kMMXEntropyRegs * 64) / 8;

inline constexpr size_t kEntropyBytes128 =
    (kVecEntropyRegs * 128 + kGPEntropyRegs * 64 + kMMXEntropyRegs * 64) / 8;

// A buffer for holding the initial or final state of a test.
// The number of bytes used depends on the microarch.
struct EntropyBuffer {
  // Alignment required for fast vector register load/store.
  uint8_t bytes[kEntropyBytes512] __attribute__((aligned(64)));

  size_t NumBytes(size_t vector_width) const {
    switch (vector_width) {
      case 512:
        return kEntropyBytes512;
      case 256:
        return kEntropyBytes256;
      case 128:
        return kEntropyBytes128;
      default:
        LOG(FATAL) << "Unsupported vector width: " << vector_width;
    }
  }
};

// Extract 64-bits worth of entropy from an arbitrary RNG.
template <typename R>
inline uint64_t GetSeed(R& rng) {
  std::uniform_int_distribution<uint64_t> dis;
  return dis(rng);
}

// Format a seed for printing in a consistent, zero-padded way.
std::string FormatSeed(uint64_t seed);
// Fill the buffer with random bytes.
void RandomizeEntropyBuffer(uint64_t seed, EntropyBuffer& buffer);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_ENTROPY_H_
