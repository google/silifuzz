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
#if defined(__aarch64__)
#include "./util/aarch64/sve.h"
#elif defined(__x86_64__)
#include <x86intrin.h>
#endif

#include "./util/arch.h"
#include "./util/reg_checksum.h"
#include "./util/reg_group_set.h"
namespace silifuzz {

// A buffer of storing register groups contents. This is only used on the
// host architecture.
// TODO: b/355239537 - De-templatize this struct.
template <typename Arch>
struct RegisterGroupIOBuffer;

// template specializations of host architecture are protected by #ifdef
// as these may pull in architecture-specific header.
#if defined(__aarch64__)
#include "./util/aarch64/reg_group_io_buffer_offsets.h"

template <>
struct RegisterGroupIOBuffer<AArch64> {
  // Register_groups describes which of the following components are active.
  //   SVE: z (vector), p (predicate), ffr (first fault register)
  // Groups not listed above are not supported yet and ignored.
  RegisterGroupSet<AArch64> register_groups;
  // Documentation for the LDR (predicate) and STR (predicate) instructions
  // indicates that loading/storing the predicate registers from memory
  // addresses with 2-byte alignment may be more efficient.
  uint8_t ffr[kSvePRegMaxSizeBytes] __attribute__((aligned(2)));
  uint8_t p[kSveNumPReg * kSvePRegMaxSizeBytes] __attribute__((aligned(2)));
  // Documentation for the LDR (vector) and STR (vector) instructions indicates
  // that loading/storing the Z registers from memory addresses with 16-byte
  // alignment may be more efficient.
  uint8_t z[kSveNumZReg * kSveZRegMaxSizeBytes] __attribute__((aligned(16)));
};

// RegisterGroupIOBuffer is used by assembly code, which needs to know struct
// member offsets defined in reg_group_io_buffer_offsets.h. Check
// here that offsets are correct.
static_assert(REGISTER_GROUP_IO_BUFFER_REGISTER_GROUPS_OFFSET ==
              offsetof(RegisterGroupIOBuffer<AArch64>, register_groups));
static_assert(REGISTER_GROUP_IO_BUFFER_FFR_OFFSET ==
              offsetof(RegisterGroupIOBuffer<AArch64>, ffr));
static_assert(REGISTER_GROUP_IO_BUFFER_P_OFFSET ==
              offsetof(RegisterGroupIOBuffer<AArch64>, p));
static_assert(REGISTER_GROUP_IO_BUFFER_Z_OFFSET ==
              offsetof(RegisterGroupIOBuffer<AArch64>, z));
#elif defined(__x86_64__)
#include "./util/x86_64/reg_group_io_buffer_offsets.h"

template <>
struct RegisterGroupIOBuffer<X86_64> {
  static constexpr size_t kNumYmms = 16;
  static constexpr size_t kNumZmms = 32;
  static constexpr size_t kNumOpmasks = 8;

  // Register_groups describes which of the following components are active.
  //   AVX: ymm
  //   AVX512: zmm and opmask
  // Groups not listed above are not supported yet and ignored.
  // TODO(dougkwan): Support more register groups.
  RegisterGroupSet<X86_64> register_groups;
  __m256 ymm[kNumYmms];
  __m512 zmm[kNumZmms];
  uint64_t opmask[kNumOpmasks];
};

// RegisterGroupIOBuffer is used by assembly code, which needs to know struct
// member offsets, which are defined in reg_group_io_buffer_offsets.h. Check
// here the offsets are correct.
static_assert(REGISTER_GROUP_IO_BUFFER_REGISTER_GROUPS_OFFSET ==
              offsetof(RegisterGroupIOBuffer<X86_64>, register_groups));
static_assert(REGISTER_GROUP_IO_BUFFER_YMM_OFFSET ==
              offsetof(RegisterGroupIOBuffer<X86_64>, ymm));
static_assert(REGISTER_GROUP_IO_BUFFER_ZMM_OFFSET ==
              offsetof(RegisterGroupIOBuffer<X86_64>, zmm));
static_assert(REGISTER_GROUP_IO_BUFFER_OPMASK_OFFSET ==
              offsetof(RegisterGroupIOBuffer<X86_64>, opmask));
#endif

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

// Returns a RegisterChecksum struct using the contents 'buffer'.  The register
// groups included in the checksum is controlled by buffer.register_groups.
RegisterChecksum<Host> GetRegisterGroupsChecksum(
    const RegisterGroupIOBuffer<Host>& buffer);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_REG_GROUP_IO_H_
