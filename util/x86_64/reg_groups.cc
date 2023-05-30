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
#include "./util/x86_64/reg_groups.h"

#include <immintrin.h>

#include <cstdint>

#include "./util/x86_64/cpu_features.h"

namespace silifuzz {

__attribute__((target("xsave"))) uint64_t GetSupportedRegisterGroups() {
  // We assume SSE is at least supported by default.
  uint64_t supported_register_groups =
      RegisterGroupBit(RegisterGroup::kGPR) |
      RegisterGroupBit(RegisterGroup::kFPR_AND_SSE);

  // Detect AVX and AVX512
  if (HasX86CPUFeature(X86CPUFeatures::kOSXSAVE)) {
    const uint64_t xcr0 = _xgetbv(0);
    constexpr uint64_t kAVXRequiredXCR0Bits = 0x6;  // YMM & XMM.
    if (HasX86CPUFeature(X86CPUFeatures::kAVX) &&
        (xcr0 & kAVXRequiredXCR0Bits) == kAVXRequiredXCR0Bits) {
      supported_register_groups |= RegisterGroupBit(RegisterGroup::kAVX);
    }

    // opmask, upper ZMM0-ZMM15, ZMM16-ZMM31, YMM & XMM.
    constexpr uint64_t kAVX512RequiredXCR0Bits = 0xe6;
    if (HasX86CPUFeature(X86CPUFeatures::kAVX512F) &&
        (xcr0 & kAVX512RequiredXCR0Bits) == kAVX512RequiredXCR0Bits) {
      supported_register_groups |= RegisterGroupBit(RegisterGroup::kAVX512);
    }
  }
  return supported_register_groups;
}

uint64_t GetChecksumRegisterGroups() {
  uint64_t checksum_register_group = GetSupportedRegisterGroups();

  // These are always recorded in snapshots and are not included in checksum.
  constexpr uint64_t kExcludedRegisterGroups =
      RegisterGroupBit(RegisterGroup::kGPR) |
      RegisterGroupBit(RegisterGroup::kFPR_AND_SSE);
  checksum_register_group &= ~kExcludedRegisterGroups;

  // If AVX512 is present, only checksum AVX512 registers.  There is no need to
  // checksum AVX registers these are contained inside AVX512 registers.
  if ((checksum_register_group & RegisterGroupBit(RegisterGroup::kAVX512)) !=
      0) {
    checksum_register_group &= ~RegisterGroupBit(RegisterGroup::kAVX);
  }

  return checksum_register_group;
}

}  // namespace silifuzz
