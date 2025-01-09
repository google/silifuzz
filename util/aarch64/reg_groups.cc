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

#include "./util/reg_groups.h"

#include "./util/aarch64/sve.h"
#include "./util/arch.h"
#include "./util/reg_group_set.h"

namespace silifuzz {

RegisterGroupSet<AArch64> GetCurrentPlatformRegisterGroups() {
  RegisterGroupSet<AArch64> groups;
  groups.SetGPR(true).SetFPR(true).SetSVEVectorWidth(GetSVEVectorWidthGlobal());
  return groups;
}

RegisterGroupSet<AArch64> GetCurrentPlatformChecksumRegisterGroups() {
  RegisterGroupSet<AArch64> groups = GetCurrentPlatformRegisterGroups();

  // These are always recorded in snapshots and are not included in checksum.
  groups.SetGPR(false).SetFPR(false);
  return groups;
}

}  // namespace silifuzz
