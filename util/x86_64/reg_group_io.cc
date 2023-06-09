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

#include "./util/reg_group_io.h"

#include <stdint.h>
#include <x86intrin.h>

#include "./util/arch.h"
#include "./util/crc32c.h"
#include "./util/reg_checksum.h"
#include "./util/reg_group_set.h"
#include "./util/x86_64/cpu_features.h"

namespace silifuzz {

// Flag to tell if AVX512 opmasks are 64-bit or not.  This is defined in
// save_registers_groups_to_buffer and set by InitRegisterGroupIO.
extern "C" bool reg_group_io_opmask_is_64_bit;

void InitRegisterGroupIO() {
  // SaveRegisterGroupsToBuffer() needs to tell if AVX512BW is supported.
  reg_group_io_opmask_is_64_bit = HasX86CPUFeature(X86CPUFeatures::kAVX512BW);
}

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

}  // namespace silifuzz
