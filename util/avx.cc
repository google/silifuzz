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

#ifdef __x86_64__
#include "./util/avx.h"

#include <immintrin.h>
#include <stdint.h>

#include <atomic>

#include "./util/x86_cpuid.h"

namespace silifuzz {
namespace {

// Information about availability of AVX-512.
enum class AVX512Info {
  kUninitialized = 0,
  // AVX512 foundation instructions supported and all zmm and mask registers
  // are accessible.
  kAvailable = 1,
  kUnavailable = 2,
};

// Whether AVX-512F is supported. This is a cached result of
// GetAVX512InfoUncached().
//
// Normally we would use a function scope static but that does not work in
// the nolibc environment. We do our own thread-safe lazy initialization so that
// this code can be used both in nolibc and google3.
std::atomic<AVX512Info> avx_512_info{AVX512Info::kUninitialized};

// For details, see 15.2 of Intel SDM vol. 1.
AVX512Info __attribute__((target("xsave"))) GetAVX512InfoOnce() {
  // Check CPU OSXSAVE feature. We need xgetbv instruction to check whether
  // all AVX-512 registers are enabled.
  X86CPUIDResult result;
  X86CPUID(1, &result);
  constexpr uint32_t kOSXSAVEFeatureBit = 1UL << 27;
  if ((result.ecx & kOSXSAVEFeatureBit) == 0) {
    return AVX512Info::kUnavailable;
  }

  // Detect AVX-512 foundation instruction support.
  X86CPUID(7, &result);
  constexpr uint32_t kAVX512FeatureBit = 1UL << 16;
  if ((result.ebx & kAVX512FeatureBit) == 0) {
    return AVX512Info::kUnavailable;
  }

  // Check AVX-512 registers.
  const uint64_t bv = _xgetbv(0);
  // This includes all xmm, ymm, zmm and mask registers.
  constexpr uint64_t kXCR0_ZMM_MASK = 0xe7;  // 111xx111b
  return ((bv & kXCR0_ZMM_MASK) == kXCR0_ZMM_MASK) ? AVX512Info::kAvailable
                                                   : AVX512Info::kUnavailable;
}

AVX512Info GetAVX512Info() {
  AVX512Info info = avx_512_info.load(std::memory_order_relaxed);
  if (info != AVX512Info::kUninitialized) return info;

  // Initialize avx_512_info.
  AVX512Info new_info = GetAVX512InfoOnce();

  // If CAS failed, info holds the current value, check whether avx_reg_info is
  // already initialized.
  while (!avx_512_info.compare_exchange_weak(info, new_info) &&
         (info == AVX512Info::kUninitialized)) {
  }

  // GetAVX512InfoOnce() should always return the same result.
  // So we just return new_info intead of loading avx_512_info again.
  return new_info;
}

}  // namespace

bool HasAVX512Registers() { return GetAVX512Info() == AVX512Info::kAvailable; }

}  // namespace silifuzz
#endif  // __x86_64__
