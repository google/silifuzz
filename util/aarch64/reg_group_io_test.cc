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

#include <cstddef>

#include "./util/aarch64/sve.h"
#include "./util/arch.h"
#include "./util/checks.h"
#include "./util/nolibc_gunit.h"
#include "./util/reg_checksum.h"
#include "./util/reg_groups.h"

namespace silifuzz {
namespace {

// Seed buffer with non-zero elements.
void SeedBuffer(RegisterGroupIOBuffer<AArch64> &buf) {
  for (int ffr_byte = 0; ffr_byte < sizeof buf.ffr; ffr_byte++) {
    buf.ffr[ffr_byte] = ffr_byte + 0xa0;
  }
  for (int p_byte = 0; p_byte < sizeof buf.p; p_byte++) {
    buf.p[p_byte] = p_byte + 0xc0;
  }
  for (int z_byte = 0; z_byte < sizeof buf.z; z_byte++) {
    buf.z[z_byte] = z_byte + 0xd0;
  }
}

// On hardware that does not support SVE, expect an empty checksum.
TEST(RegisterGroupIO, GetRegisterGroupChecksumWithoutSVE) {
  InitRegisterGroupIO();
  RegisterGroupIOBuffer<AArch64> buffer;
  buffer.register_groups = GetCurrentPlatformChecksumRegisterGroups();

  if (buffer.register_groups.GetSVEVectorWidth()) {
    SILIFUZZ_TEST_SKIP();
  }

  SaveRegisterGroupsToBuffer(buffer);

  RegisterChecksum<AArch64> register_checksum =
      GetRegisterGroupsChecksum(buffer);
  RegisterChecksum<AArch64> empty_checksum{};
  CHECK(register_checksum == empty_checksum);
}

TEST(RegisterGroupIO, GetRegisterGroupChecksumWithSVE) {
  InitRegisterGroupIO();
  RegisterGroupIOBuffer<AArch64> buffer;
  buffer.register_groups = GetCurrentPlatformChecksumRegisterGroups();

  if (!buffer.register_groups.GetSVEVectorWidth()) {
    SILIFUZZ_TEST_SKIP();
  }

  SeedBuffer(buffer);
  RegisterChecksum<AArch64> seed_checksum = GetRegisterGroupsChecksum(buffer);
  RegisterChecksum<AArch64> empty_checksum{};

  SaveRegisterGroupsToBuffer(buffer);
  RegisterChecksum<AArch64> register_checksum =
      GetRegisterGroupsChecksum(buffer);
  CHECK(register_checksum != seed_checksum);
  CHECK(register_checksum != empty_checksum);
}

TEST(RegisterGroupIO, GetSVEZRegistersChecksumOnRightVectorLength) {
  InitRegisterGroupIO();
  const uint16_t sve_vector_width = 32;
  RegisterGroupIOBuffer<AArch64> buffer;
  buffer.register_groups.SetSVEVectorWidth(sve_vector_width);

  RegisterChecksum<AArch64> initial_checksum =
      GetRegisterGroupsChecksum(buffer);
  // Only the first sve_vector_width * kSveNumZReg bytes in buffer.z should be
  // used in the checksum. This should not affect the checksum result.
  const size_t active_z_buffer_size = sve_vector_width * kSveNumZReg;
  for (int i = active_z_buffer_size; i < sizeof(buffer.z); i++) {
    buffer.z[i] = 1;
  }
  RegisterChecksum<AArch64> checksum_not_changed =
      GetRegisterGroupsChecksum(buffer);

  buffer.z[active_z_buffer_size - 1] = 1;
  RegisterChecksum<AArch64> checksum_changed =
      GetRegisterGroupsChecksum(buffer);
  CHECK(checksum_not_changed == initial_checksum);
  CHECK(checksum_changed != initial_checksum);
}

TEST(RegisterGroupIO, GetSVEPRegistersChecksumOnRightVectorLength) {
  InitRegisterGroupIO();
  const uint16_t sve_vector_width = 32;
  RegisterGroupIOBuffer<AArch64> buffer;
  buffer.register_groups.SetSVEVectorWidth(sve_vector_width);

  RegisterChecksum<AArch64> initial_checksum =
      GetRegisterGroupsChecksum(buffer);

  // Only the first sve_vector_width / kSvePRegSizeZRegFactor * kSveNumPReg
  // bytes in buffer.p should be used in the checksum. This should not affect
  // the checksum result.
  const size_t active_p_buffer_size =
      sve_vector_width / kSvePRegSizeZRegFactor * kSveNumPReg;
  for (int i = active_p_buffer_size; i < sizeof(buffer.p); i++) {
    buffer.p[i] = 1;
  }
  RegisterChecksum<AArch64> checksum_not_changed =
      GetRegisterGroupsChecksum(buffer);

  buffer.p[active_p_buffer_size - 1] = 1;
  RegisterChecksum<AArch64> checksum_changed =
      GetRegisterGroupsChecksum(buffer);
  CHECK(checksum_not_changed == initial_checksum);
  CHECK(checksum_changed != initial_checksum);
}

}  // namespace
}  // namespace silifuzz

// ========================================================================= //

NOLIBC_TEST_MAIN({
  RUN_TEST(RegisterGroupIO, GetRegisterGroupChecksumWithoutSVE);
  RUN_TEST(RegisterGroupIO, GetRegisterGroupChecksumWithSVE);
  RUN_TEST(RegisterGroupIO, GetSVEZRegistersChecksumOnRightVectorLength);
  RUN_TEST(RegisterGroupIO, GetSVEPRegistersChecksumOnRightVectorLength);
})
