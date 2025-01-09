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

#include "./util/reg_group_bits.h"
#include "./util/aarch64/reg_group_io_buffer_offsets.h"
        .text

        .p2align 4
        .globl  SaveRegisterGroupsToBuffer
        .type   SaveRegisterGroupsToBuffer, @function

// This is equivalent to:
//
// void SaveRegisterGroupsToBuffer(RegisterGroupIOBuffer<AArch64>& buffer) {
//   uint64_t mask = buffer.register_groups.Serialize();
//   if (mask & AARCH64_SVE_VECTOR_WIDTH_MASK != 0) {
//     StoreZRegisters(&buffer.z);
//     StorePRegisters(&buffer.p);
//     StoreFfrRegister(&buffer.ffr);
//   }
// }
//
// For simplicity, we use separate functions to save the extension registers.
// If performance turns out to be an issue, we can inline the saving sequences
// to avoid the cost of calling and returning.
//
SaveRegisterGroupsToBuffer:
        // Save contents of x19 because we want to use it in this function.
        // Save return address (x30).
        stp     x19, x30, [sp, #-16]!
        // Save buffer address across subroutine branches.
        mov     x19, x0

        // Check register groups bitmask for SVE group.
        add     x1, x19, #REGISTER_GROUP_IO_BUFFER_REGISTER_GROUPS_OFFSET
        ldr     x1, [x1]
        and     x1, x1, #AARCH64_SVE_VECTOR_WIDTH_MASK
        cbz     x1, Exit

SaveSve:
        add     x0, x19, #REGISTER_GROUP_IO_BUFFER_Z_OFFSET
        bl      StoreZRegisters
        add     x0, x19, #REGISTER_GROUP_IO_BUFFER_P_OFFSET
        bl      StorePRegisters
        add     x0, x19, #REGISTER_GROUP_IO_BUFFER_FFR_OFFSET
        bl      StoreFfrRegister

Exit:
        // Restore x19 and return address.
        ldp     x19, x30, [sp], #16
        ret
        .size   SaveRegisterGroupsToBuffer, .-SaveRegisterGroupsToBuffer
