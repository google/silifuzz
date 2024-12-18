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

        .text

        .p2align 4
        .globl  ClearRegisterGroups
        .type   ClearRegisterGroups, @function

// This is equivalent to:
//
// void ClearRegisterGroups() {
//   if (reg_group_io_sve_vector_width) {
//     ClearPRegisters();
//     ClearFfrRegister();
//   }
// }
//
// For simplicity, we use separate functions to clear the extension registers.
// If performance turns out to be an issue, we can inline the sequences to
// avoid the cost of calling and returning.
//
// Note: We skip clearing the Z registers as writes to V floating point
// registers already clear the Z registers from [128 bits, vector_length). This
// is because the V registers share the bottom 128-bits of the Z registers.
//
ClearRegisterGroups:
        // Save x30 (return address) and x9.
        stp     x30, x9, [sp, #-16]!

        // Check that SVE is supported.
        adrp    x9, reg_group_io_sve_vector_width
        add     x9, x9, :lo12:reg_group_io_sve_vector_width
        ldrh    w9, [x9]
        cbz     w9, Exit

ClearSve:
        bl      ClearPRegisters
        bl      ClearFfrRegister

Exit:
        // Restore x30 (return address) and x9.
        ldp     x30, x9, [sp], #16
        ret
        .size   ClearRegisterGroups, .-ClearRegisterGroups
