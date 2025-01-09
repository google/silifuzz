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

#include "./util/aarch64/sve.h"
#include "./util/arch.h"
#include "./util/crc32c.h"
#include "./util/reg_checksum.h"
#include "./util/reg_group_set.h"

namespace silifuzz {

void InitRegisterGroupIO() {
  SetSVEVectorWidthGlobal(SveGetCurrentVectorLength());
}

RegisterChecksum<AArch64> GetRegisterGroupsChecksum(
    const RegisterGroupIOBuffer<AArch64>& buffer) {
  uint32_t crc = 0;
  RegisterChecksum<AArch64> register_checksum;

  const RegisterGroupSet<AArch64>& groups = buffer.register_groups;
  const uint16_t sve_vector_width = groups.GetSVEVectorWidth();
  if (sve_vector_width) {
    crc = crc32c(crc, reinterpret_cast<const uint8_t*>(buffer.ffr),
                 sizeof(buffer.ffr));
    crc = crc32c(crc, reinterpret_cast<const uint8_t*>(buffer.p),
                 sizeof(buffer.p));
    crc = crc32c(crc, reinterpret_cast<const uint8_t*>(buffer.z),
                 sizeof(buffer.z));
    register_checksum.register_groups.SetSVEVectorWidth(sve_vector_width);
  }

  register_checksum.checksum = crc;
  return register_checksum;
}

}  // namespace silifuzz
