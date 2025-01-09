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

#include "./util/arch.h"
#include "./util/checks.h"
#include "./util/nolibc_gunit.h"
#include "./util/reg_checksum.h"
#include "./util/reg_group_set.h"
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

}  // namespace
}  // namespace silifuzz

// ========================================================================= //

NOLIBC_TEST_MAIN({
  RUN_TEST(RegisterGroupIO, GetRegisterGroupChecksumWithoutSVE);
  RUN_TEST(RegisterGroupIO, GetRegisterGroupChecksumWithSVE);
})
