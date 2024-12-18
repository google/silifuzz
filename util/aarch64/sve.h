// Copyright 2024 The SiliFuzz Authors.
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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_AARCH64_SVE_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_AARCH64_SVE_H_

#include <asm/sigcontext.h>
#include <errno.h>
#include <sys/prctl.h>

#include <cstddef>

#include "./util/checks.h"
#include "./util/itoa.h"

namespace silifuzz {

// SVE hardware has z0-z31 (vector), p0-p15 (predicate), and ffr (first fault
// register).
inline constexpr size_t kSveNumZReg = 32;
inline constexpr size_t kSveNumPReg = 16;

// The SVE Z registers have a max size of 256 bytes (2048 bits).
inline constexpr size_t kSveZRegMaxSizeBytes = 256;
// The SVE Z registers have a size alignment of 16 bytes (128 bits).
inline constexpr size_t kSveZRegSizeAlignmentBytes = 16;
// The SVE P registers are fixed to 1/8th the size of the Z registers.
inline constexpr size_t kSvePRegSizeZRegFactor = 8;
// The SVE P registers have a max size of 32 bytes (256 bits).
inline constexpr size_t kSvePRegMaxSizeBytes =
    kSveZRegMaxSizeBytes / kSvePRegSizeZRegFactor;

// Flag to store the vector width of SVE in bytes, or 0 if SVE is not supported.
// Defined in sve_vector_width.S and set by InitRegisterGroupIO.
extern "C" uint16_t reg_group_io_sve_vector_width;

// Returns the length of the Z registers in bytes if SVE is supported. Returns
// 0 if SVE is not supported.
inline size_t SveGetCurrentVectorLength() {
  int z_len = prctl(PR_SVE_GET_VL);
  // Negative value indicates an error and/or that SVE is not supported.
  if (z_len < 0) {
    VLOG_INFO(0, "SVE is most likely not supported on this platform: ",
              ErrnoStr(errno));
    return 0;
  }
  return z_len & PR_SVE_VL_LEN_MASK;
}

// Requests the kernel to set the specified vector length (in bytes). Returns
// the actual vector length set by the kernel or 0 if SVE is not supported.
inline size_t SveSetCurrentVectorLength(size_t length) {
  CHECK_EQ(length & ~PR_SVE_VL_LEN_MASK, 0);
  int z_len = prctl(PR_SVE_SET_VL, length);
  if (z_len < 0) {
    VLOG_INFO(0, "SVE is most likely not supported on this platform: ",
              ErrnoStr(errno));
    return 0;
  }
  return z_len & PR_SVE_VL_LEN_MASK;
}

// Requests the kernel to set to the max supported vector length. Returns the
// actual vector length (in bytes) or 0 if SVE is not supported.
inline size_t SveSetMaxVectorLength() {
  return SveSetCurrentVectorLength(SVE_VL_MAX);
}

// Returns the length of the P registers in bytes if SVE is supported. Returns
// 0 if SVE is not supported.
inline size_t SveGetPredicateLength() {
  return SveGetCurrentVectorLength() / kSvePRegSizeZRegFactor;
}

// Returns true if the hardware supports SVE. Makes a syscall, so cannot be
// called after entering seccomp mode.
inline bool SveIsSupported() { return SveGetCurrentVectorLength() > 0; }

// Returns the vector width of SVE in bytes, or 0 if SVE is not supported. This
// function only fetches the global variable and does not make a syscall.
inline uint16_t GetSVEVectorWidthGlobal() {
  return reg_group_io_sve_vector_width;
}

// Sets the vector width of SVE in bytes. This function only sets the global
// variable and does not make a syscall.
inline void SetSVEVectorWidthGlobal(uint16_t sve_vector_width) {
  reg_group_io_sve_vector_width = sve_vector_width;
}

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_AARCH64_SVE_H_
