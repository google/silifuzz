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

#include "./util/reg_group_bits.h"
#include "./util/x86_64/reg_group_io_buffer_offsets.h"
        .text

        .p2align 4
        .globl  SaveRegisterGroupsToBuffer
        .type   SaveRegisterGroupsToBuffer, @function

// This is equivalent to:
//
// void SaveRegisterGroupsToBuffer(RegisterGroupIOBuffer<x86_64>& buffer) {
//   uint64_t mask = buffer.register_groups.Serialize();
//   if (mask & X86_REG_GROUP_AVX != 0) {
//     save_ymm_registers(&buffer.ymm);
//   }
//   if (mask &  X86_REG_GROUP_AVX512 != 0) {
//     save_zmm_registers(&buffer.zmm);
//     /* save opmasks only if we save zmm registers. */
//     if (reg_group_io_opmask_is_64_bit) {
//       save_opmask_registers_64(&buffer.opmask);
//     } else {
//       save_opmask_registers_16(&buffer.opmask);
//     }
//   }
// }
//
// For simplicty, we use separate functions to save the extension registers.
// If performance turns out to be an issue, we can inline the saving sequences
// to avoid the cost of calling and returning.
//
SaveRegisterGroupsToBuffer:
        push   %rbp
        mov    %rsp, %rbp

        // Save callee-saved registers.
        push    %rbx
        push    %r12

        mov     %rdi, %rbx  // rbx now holds 'buffer'

        // Load register group mask into r12
        mov     REGISTER_GROUP_IO_BUFFER_REGISTER_GROUPS_OFFSET(%rbx), %r12

        // Check saving AVX group
        test    $X86_REG_GROUP_AVX, %r12
        je      .Lcheck_avx512
        lea     REGISTER_GROUP_IO_BUFFER_YMM_OFFSET(%rbx), %rdi
        call    save_ymm_registers

        // Check saving AVX512 group
.Lcheck_avx512:
        test    $X86_REG_GROUP_AVX512, %r12
        je      .Lexit
        lea     REGISTER_GROUP_IO_BUFFER_ZMM_OFFSET(%rbx), %rdi
        call    save_zmm_registers

        // For opmask, we need to check the size of opmasks.
        lea     REGISTER_GROUP_IO_BUFFER_OPMASK_OFFSET(%rbx), %rdi
        movzb   reg_group_io_opmask_is_64_bit(%rip), %rsi
        test    %rsi, %rsi
        je      .Lsave_opmask_16
        pop     %r12
        pop     %rbx
        pop     %rbp
        jmp     save_opmask_registers_64  // tail call.

.Lsave_opmask_16:
        pop     %r12
        pop     %rbx
        pop     %rbp
        jmp     save_opmask_registers_16 // tail call.

.Lexit:
        // Restore callee-saved registers and return.
        pop     %r12
        pop     %rbx
        pop     %rbp
        ret
        .size   SaveRegisterGroupsToBuffer, .-SaveRegisterGroupsToBuffer

        .bss
// Flag to tell if AVX512 opmasks are 64-bit or not.
// We use it to determine what instructions to used to access opmasks.
        .align  1
        .globl  reg_group_io_opmask_is_64_bit
        .type   reg_group_io_opmask_is_64_bit, @object
        .size   reg_group_io_opmask_is_64_bit, 1
reg_group_io_opmask_is_64_bit:
        .zero   1

        .section        .note.GNU-stack,"",@progbits
