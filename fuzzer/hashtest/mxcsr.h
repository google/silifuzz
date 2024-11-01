// Copyright 2024 The Silifuzz Authors.
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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_MXCSR_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_MXCSR_H_

#include <cstdint>

namespace silifuzz {

inline uint32_t GetMxcsr() {
  uint32_t mxcsr;
  asm volatile("stmxcsr %0" : "=m"(mxcsr));
  return mxcsr;
}

inline void SetMxcsr(uint32_t mxcsr) {
  asm volatile("ldmxcsr %0" : : "m"(mxcsr));
}

enum MXCSR : uint32_t {
  kMXCSRInvalidOperationFlag = 1 << 0U,
  kMXCSRDenormalFlag = 1 << 1U,
  kMXCSRDivideByZeroFlag = 1 << 2U,
  kMXCSROverflowFlag = 1 << 3U,
  kMXCSRUnderflowFlag = 1 << 4U,
  kMXCSRPercisionFlag = 1 << 5U,

  kMXCSRDenormalsAreZeros = 1 << 6U,

  kMXCSRInvalidOperationMask = 1 << 7U,
  kMXCSRDenormalOperationMask = 1 << 8U,
  kMXCSRDivideByZeroMask = 1 << 9U,
  kMXCSROverflowMask = 1 << 10U,
  kMXCSRUnderflowMask = 1 << 11U,
  kMXCSRPercisionMask = 1 << 12U,
  kMXCSRMaskAll = kMXCSRInvalidOperationMask | kMXCSRDenormalOperationMask |
                  kMXCSRDivideByZeroMask | kMXCSROverflowMask |
                  kMXCSRUnderflowMask | kMXCSRPercisionMask,

  kMXCSRRoundNearest = 0,
  kMXCSRRoundDown = 1 << 13U,
  kMXCSRRoundUp = 1 << 14U,
  kMXCSRRoundTowardsZero = (1 << 13U) | (1 << 14U),

  kMXCSRFlushToZero = 1 << 15U,
};

static_assert(kMXCSRMaskAll == 0x1f80, "MXCSR mask all value is unexpected.");

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_MXCSR_H_
