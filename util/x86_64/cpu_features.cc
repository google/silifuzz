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

#ifdef __x86_64__
#include "./util/x86_64/cpu_features.h"

#include <atomic>
#include <cstdint>

#include ".//util/x86_cpuid.h"

namespace silifuzz {
namespace {

static constexpr uint64_t kInitializedBitMask = static_cast<uint64_t>(1) << 63;

// Normally we would use a function scope static but that does not work in
// the nolibc environment. We do our own thread-safe lazy initialization so that
// this code can be used both in nolibc and google3.
std::atomic<uint64_t> x86_cpu_features;
static_assert(x86_cpu_features.is_always_lock_free);

inline bool IsBitSet(uint64_t bitmask, size_t pos) {
  return (bitmask & (static_cast<uint64_t>(1) << pos)) != 0;
}

uint64_t GetX86CPUFeatures() {
  uint64_t features = kInitializedBitMask;
  X86CPUIDResult cpuid_result;
  X86CPUID(1, &cpuid_result);

  // CPUID.0x1:ECX.XSAVE[bit 26]
  if (IsBitSet(cpuid_result.ecx, 26)) {
    features |= X86CPUFeatureBitmask(X86CPUFeatures::kXSAVE);
  }
  // CPUID.0x1:ECX.OSXSAVE[bit 27]
  if (IsBitSet(cpuid_result.ecx, 27)) {
    features |= X86CPUFeatureBitmask(X86CPUFeatures::kOSXSAVE);
  }
  // CPUID.0x1:ECX.AVX[bit 28]
  if (IsBitSet(cpuid_result.ecx, 28)) {
    features |= X86CPUFeatureBitmask(X86CPUFeatures::kAVX);
  }

  // CPUID.0x1:EDX.SSE[bit 25]
  if (IsBitSet(cpuid_result.edx, 25)) {
    features |= X86CPUFeatureBitmask(X86CPUFeatures::kSSE);
  }

  X86CPUID(7, &cpuid_result);
  // CPUID.0x7.0:EBX.AVX512F[bit 16]
  if (IsBitSet(cpuid_result.ebx, 16)) {
    features |= X86CPUFeatureBitmask(X86CPUFeatures::kAVX512F);
  }
  // CPUID.0x7.0:EBX.AVX512BW[bit 30]
  if (IsBitSet(cpuid_result.ebx, 30)) {
    features |= X86CPUFeatureBitmask(X86CPUFeatures::kAVX512BW);
  }
  // CPUID.0x7.0:EDX.AMXTILE[bit 24]
  if (IsBitSet(cpuid_result.edx, 24)) {
    features |= X86CPUFeatureBitmask(X86CPUFeatures::kAMX_TILE);
  }
  return features;
}

}  // namespace

bool HasX86CPUFeature(X86CPUFeatures feature) {
  uint64_t features = x86_cpu_features.load(std::memory_order_relaxed);
  if (features & kInitializedBitMask) {
    return (features & X86CPUFeatureBitmask(feature)) != 0;
  }

  const uint64_t new_features = GetX86CPUFeatures();

  // If CAS failed, 'features' holds the current value. Check whether it is
  // already initialized.
  while (!x86_cpu_features.compare_exchange_weak(features, new_features) &&
         (features & kInitializedBitMask) == 0) {
  }

  // GetX86CPUFeatures() should always return the same result.
  return (new_features & X86CPUFeatureBitmask(feature));
}

}  // namespace silifuzz
#endif  // __x86_64__
