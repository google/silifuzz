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

#include "./util/reg_groups.h"

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "./util/aarch64/sve.h"
#include "./util/arch.h"
#include "./util/checks.h"
#include "./util/nolibc_gunit.h"

namespace silifuzz {
namespace {

TEST(RegisterGroups, CurrentPlatformRegisterGroupsWithoutSVE) {
  SetSVEVectorWidthGlobal(0);
  RegisterGroupSet<AArch64> groups = GetCurrentPlatformRegisterGroups();
  RegisterGroupSet<AArch64> expected;
  expected.SetGPR(true).SetFPR(true);
  CHECK(groups == expected);
}

TEST(RegisterGroups, CurrentPlatformRegisterGroupsWithSVE) {
  SetSVEVectorWidthGlobal(16);
  RegisterGroupSet<AArch64> groups = GetCurrentPlatformRegisterGroups();
  RegisterGroupSet<AArch64> expected;
  expected.SetGPR(true).SetFPR(true).SetSVE(true);
  CHECK(groups == expected);

  // Make sure double-byte vector length also works.
  SetSVEVectorWidthGlobal(0x100);
  RegisterGroupSet<AArch64> groups_db = GetCurrentPlatformRegisterGroups();
  CHECK(groups_db == expected);
}

TEST(RegisterGroups, CurrentPlatformChecksumRegisterGroups) {
  RegisterGroupSet<AArch64> groups = GetCurrentPlatformChecksumRegisterGroups();

  // These should not be in a checksum.
  CHECK(!groups.GetGPR() && !groups.GetFPR());

  // Clear all other known checksum bits to ensure no unexpected bits are set.
  groups.SetSVE(false);
  CHECK(groups.Empty());
}

}  // namespace
}  // namespace silifuzz

// ========================================================================= //

NOLIBC_TEST_MAIN({
  RUN_TEST(RegisterGroups, CurrentPlatformRegisterGroupsWithoutSVE);
  RUN_TEST(RegisterGroups, CurrentPlatformRegisterGroupsWithSVE);
  RUN_TEST(RegisterGroups, CurrentPlatformChecksumRegisterGroups);
})
