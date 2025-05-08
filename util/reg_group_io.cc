// Copyright 2025 The SiliFuzz Authors.
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
#include "./util/reg_group_io.h"

#include <cstdint>
#include <cstring>

#include "./util/arch.h"
#include "./util/checks.h"
#include "./util/crc32c.h"
#include "./util/reg_checksum.h"
#include "./util/reg_group_set.h"
#include "./util/sve_constants.h"

namespace silifuzz {

// Computes a CRC32C checksum of registers groups in 'buffer'.
//
// Registers data are visited in this order:
//
// ymm0-ymm15 if AVX is support but AVX512F is not supported by host.
// zmm0-zmm31 if AVX512F is supported by host.
// k0-k7 if AVX512F is supported by host.
//
// For each group of registers, data are read as little-endian byte image
// according to register number ordering.  For example, the LSB of zmm0 is
// read first and the MSB of zmm31 is read last when checksumming AVX512
// registers.
template <>
RegisterChecksum<X86_64> GetRegisterGroupsChecksum(
    const RegisterGroupIOBuffer<X86_64>& buffer) {
  uint32_t crc = 0;
  RegisterChecksum<X86_64> register_checksum;

  const RegisterGroupSet<X86_64>& groups = buffer.register_groups;
  if (groups.GetAVX()) {
    crc = crc32c(crc, reinterpret_cast<const uint8_t*>(buffer.ymm),
                 sizeof(buffer.ymm));
    register_checksum.register_groups.SetAVX(true);
  }

  if (groups.GetAVX512()) {
    crc = crc32c(crc, reinterpret_cast<const uint8_t*>(buffer.zmm),
                 sizeof(buffer.zmm));
    crc = crc32c(crc, reinterpret_cast<const uint8_t*>(buffer.opmask),
                 sizeof(buffer.opmask));
    register_checksum.register_groups.SetAVX512(true);
  }

  register_checksum.checksum = crc;
  return register_checksum;
}

template <>
RegisterChecksum<AArch64> GetRegisterGroupsChecksum(
    const RegisterGroupIOBuffer<AArch64>& buffer) {
  uint32_t crc = 0;
  RegisterChecksum<AArch64> register_checksum;

  const RegisterGroupSet<AArch64>& groups = buffer.register_groups;
  const uint16_t sve_vector_width = groups.GetSVEVectorWidth();
  if (sve_vector_width) {
    CHECK_GE(sve_vector_width, 16);
    CHECK_LE(sve_vector_width, kSveZRegMaxSizeBytes);
    // `ffr_with_padding` is used for backwards compatibility reasons: the first
    // version of the SVE registers checksum is calculated with the entire FFR
    // register region in the RegisterGroupIOBuffer. In practice, only active
    // bytes of FFR region are set to non-zero values, so that is equivalent to
    // checksumming on a fixed 32-byte region starting with active bytes, and
    // followed by 0 paddings.
    uint8_t ffr_with_padding[kSvePRegMaxSizeBytes]{0};
    memcpy(ffr_with_padding, buffer.ffr,
           SveFfrActiveSizeBytes(sve_vector_width));
    crc = crc32c(crc, ffr_with_padding, sizeof(ffr_with_padding));
    crc = crc32c(crc, buffer.p, SvePRegActiveSizeBytes(sve_vector_width));
    crc = crc32c(crc, buffer.z, SveZRegActiveSizeBytes(sve_vector_width));
    register_checksum.register_groups.SetSVEVectorWidth(sve_vector_width);
  }

  register_checksum.checksum = crc;
  return register_checksum;
}

bool RegisterGroupIOBuffer<X86_64>::operator==(
    const RegisterGroupIOBuffer<X86_64>& other) const {
  return GetRegisterGroupsChecksum(*this) == GetRegisterGroupsChecksum(other);
}

bool RegisterGroupIOBuffer<AArch64>::operator==(
    const RegisterGroupIOBuffer<AArch64>& other) const {
  return GetRegisterGroupsChecksum(*this) == GetRegisterGroupsChecksum(other);
}

}  // namespace silifuzz
