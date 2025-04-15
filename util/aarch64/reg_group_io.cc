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

#include "./util/aarch64/reg_group_io_buffer_offsets.h"
#include "./util/aarch64/sve.h"
#include "./util/arch.h"

namespace silifuzz {

// RegisterGroupIOBuffer is used by assembly code, which needs to know struct
// member offsets of the host architecture, which are defined in
// reg_group_io_buffer_offsets.h. Check here that offsets are correct.
static_assert(REGISTER_GROUP_IO_BUFFER_REGISTER_GROUPS_OFFSET ==
              offsetof(RegisterGroupIOBuffer<AArch64>, register_groups));
static_assert(REGISTER_GROUP_IO_BUFFER_FFR_OFFSET ==
              offsetof(RegisterGroupIOBuffer<AArch64>, ffr));
static_assert(REGISTER_GROUP_IO_BUFFER_P_OFFSET ==
              offsetof(RegisterGroupIOBuffer<AArch64>, p));
static_assert(REGISTER_GROUP_IO_BUFFER_Z_OFFSET ==
              offsetof(RegisterGroupIOBuffer<AArch64>, z));

void InitRegisterGroupIO() {
  SetSVEVectorWidthGlobal(SveGetCurrentVectorLength());
}

}  // namespace silifuzz
