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

// Currently we do not do checksumming on AArch64. This test just that.
// We get the expected empty value.
TEST(RegisterGroupIO, GetRegisterGroupChecksum) {
  RegisterGroupSet<AArch64> checksum_register_group =
      GetCurrentPlatformChecksumRegisterGroups();
  RegisterGroupIOBuffer<AArch64> buffer;
  buffer.register_groups = checksum_register_group;

  // This should be a NOP
  SaveRegisterGroupsToBuffer(buffer);

  RegisterChecksum<AArch64> register_checksum =
      GetRegisterGroupsChecksum(buffer);
  RegisterChecksum<AArch64> empty_checksum{};
  CHECK(register_checksum == empty_checksum);
}

}  // namespace
}  // namespace silifuzz

// ========================================================================= //

NOLIBC_TEST_MAIN({ RUN_TEST(RegisterGroupIO, GetRegisterGroupChecksum); })
