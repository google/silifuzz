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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_X86_64_REG_GROUPS_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_X86_64_REG_GROUPS_H_
#include <cstdint>

namespace silifuzz {

// Register groups on the X86-64 architecture. This particular grouping is done
// for ease of representing register state in a variable-sized structure.
enum class RegisterGroup {
  kGPR = 0,  // All GPRs.

  // Legacy x87 / MMX and 128-bit SSE registers xmm0-xmm15. These include the
  // stack registers and various special registers. In practice these are saved
  // and restored together with the SSE registers since there is no instruction
  // to handled x87 and SSE states separately in 64-bit mode. FXSAVE and FXRSTOR
  // handle both kinds of registers together.
  kFPR_AND_SSE = 1,

  // 256-bit AVX registers ymm0-ymm15.  These include bits in SSE registers
  // xmm0-xmm7.
  kAVX = 2,

  // 512-bit AVX512 registers zmm0-zmm31 and opmask registers k0-k7. The
  // registers zmm0-zmm15 include bits in AVX and SSE registers. The maximum bit
  // size of opmasks is MAX_KL(64 bits) but AVX512 foundation instructions
  // support accessing only the lowest 16 bits of those. Accessing the upper 48
  // bits requires AVX512BW features. The opmasks are stored our data structures
  // as full 64-bit integers regardless with the upper 48 bits cleared or
  // ignored when AVX512BW is absent.
  kAVX512 = 3,

  // Bounds for iteration.
  kBEGIN = kGPR,
  kEND = kAVX512 + 1,
};

constexpr uint64_t RegisterGroupBit(RegisterGroup group) {
  return static_cast<uint64_t>(1) << static_cast<int>(group);
}

// Returns a bit mask for supported register groups.
uint64_t GetSupportedRegisterGroups();

// Returns a bit mask for registers groups for which a checksum is computed
// at the end of snapshot execution. These registers are not fully recorded
// after snapshot execution and thus only summary information is available.
uint64_t GetChecksumRegisterGroups();

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_X86_64_REG_GROUPS_H_
