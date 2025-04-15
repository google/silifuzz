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

#include <cstddef>

#include "./util/arch.h"
#include "./util/cpu_features.h"
#include "./util/x86_64/reg_group_io_buffer_offsets.h"

namespace silifuzz {

// Flag to tell if AVX512 opmasks are 64-bit or not.  This is defined in
// save_registers_groups_to_buffer and set by InitRegisterGroupIO.
extern "C" unsigned char reg_group_io_opmask_is_64_bit;

// RegisterGroupIOBuffer is used by assembly code, which needs to know struct
// member offsets of the host architecture, which are defined in
// reg_group_io_buffer_offsets.h. Check here the offsets are correct.
static_assert(REGISTER_GROUP_IO_BUFFER_REGISTER_GROUPS_OFFSET ==
              offsetof(RegisterGroupIOBuffer<X86_64>, register_groups));
static_assert(REGISTER_GROUP_IO_BUFFER_YMM_OFFSET ==
              offsetof(RegisterGroupIOBuffer<X86_64>, ymm));
static_assert(REGISTER_GROUP_IO_BUFFER_ZMM_OFFSET ==
              offsetof(RegisterGroupIOBuffer<X86_64>, zmm));
static_assert(REGISTER_GROUP_IO_BUFFER_OPMASK_OFFSET ==
              offsetof(RegisterGroupIOBuffer<X86_64>, opmask));

void InitRegisterGroupIO() {
  // SaveRegisterGroupsToBuffer() needs to tell if AVX512BW is supported.
  reg_group_io_opmask_is_64_bit = HasX86CPUFeature(X86CPUFeatures::kAVX512BW);
}

}  // namespace silifuzz
