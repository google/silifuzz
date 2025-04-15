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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_REG_GROUP_IO_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_REG_GROUP_IO_H_

// Register group I/O.
// This library has global states. It is intended to be used by the runner
// so locking is normally not required.  If it is ever used in a multi-threaded
// environment, access needs to be controlled by a lock. Currently this
// is only used for computing register checksums.

#include <cstddef>
#include <cstdint>

#include "./util/arch.h"
#include "./util/reg_checksum.h"
#include "./util/reg_group_set.h"
#include "./util/sve_constants.h"

namespace silifuzz {

// A buffer of storing register groups contents.
template <typename Arch>
struct RegisterGroupIOBuffer;

template <>
struct RegisterGroupIOBuffer<X86_64> {
  static constexpr size_t kNumYmms = 16;
  static constexpr size_t kNumZmms = 32;
  static constexpr size_t kNumOpmasks = 8;
  static constexpr size_t kYmmSizeBytes = 32;
  static constexpr size_t kZmmSizeBytes = 64;

  // Register_groups describes which of the following components are active.
  //   AVX: ymm
  //   AVX512: zmm and opmask
  // Groups not listed above are not supported yet and ignored.
  // TODO(dougkwan): Support more register groups.
  RegisterGroupSet<X86_64> register_groups;
  // Ymm and zmm need to be aligned to 32-bit and 64-bit respectively so that
  // they can be used with the vmovdqa/vmovdqa32 instruction.
  alignas(kYmmSizeBytes) uint8_t ymm[kNumYmms][kYmmSizeBytes];
  alignas(kZmmSizeBytes) uint8_t zmm[kNumZmms][kZmmSizeBytes];
  uint64_t opmask[kNumOpmasks];
};

template <>
struct RegisterGroupIOBuffer<AArch64> {
  // Register_groups describes which of the following components are active.
  //   SVE: z (vector), p (predicate), ffr (first fault register)
  // Groups not listed above are not supported yet and ignored.
  RegisterGroupSet<AArch64> register_groups;
  // SVE register sizes are dynamic. Use 1d array for the buffer so that we can
  // keep the data compacted when vector length is small. This helps reduce the
  // checksumming overhead.
  // Documentation for the LDR (predicate) and STR (predicate) instructions
  // indicates that loading/storing the predicate registers from memory
  // addresses with 2-byte alignment may be more efficient.
  alignas(kSvePRegSizeAlignmentBytes) uint8_t ffr[kSvePRegMaxSizeBytes];
  alignas(
      kSvePRegSizeAlignmentBytes) uint8_t p[kSveNumPReg * kSvePRegMaxSizeBytes];
  // Documentation for the LDR (vector) and STR (vector) instructions indicates
  // that loading/storing the Z registers from memory addresses with 16-byte
  // alignment may be more efficient.
  alignas(
      kSveZRegSizeAlignmentBytes) uint8_t z[kSveNumZReg * kSveZRegMaxSizeBytes];
};

// Initialize register group I/O library. This needs to be called once
// before calling any other functions in the library. This operation is
// idempotent.
void InitRegisterGroupIO();

// Saves current contents of registers into 'buffer'. The register groups saved
// are controlled by buffer.register_groups. This function is in the
// "C" namespace as it is used by runner run-time written in assembly. The
// runner calls this function at the exit of a Snap to save register contents
// for checksumming.
extern "C" void SaveRegisterGroupsToBuffer(RegisterGroupIOBuffer<Host>& buffer);

// Clears the registers that are not part of the ucontext and instead saved into
// RegisterGroupIOBuffers. This function is used in RestoreUContext.
extern "C" void ClearRegisterGroups();

// Returns a RegisterChecksum struct using the contents 'buffer'.  The register
// groups included in the checksum is controlled by buffer.register_groups.
RegisterChecksum<Host> GetRegisterGroupsChecksum(
    const RegisterGroupIOBuffer<Host>& buffer);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_REG_GROUP_IO_H_
