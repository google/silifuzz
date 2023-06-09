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

//
// Assembly helpers for reg_group_io_test
//
        .text

       .p2align 4
        .globl  SaveAVXTestDataToRegisterGroupsBuffer
        .type   SaveAVXTestDataToRegisterGroupsBuffer, @function

// This is equivalent to:
//
// void SaveAVXTestDataToRegisterGroupsBuffer(
//   const __m256* ymm, RegisterGroupIOBuffer<X86_64>& buffer) {
//   load_ymm_registers(ymm);
//   SaveRegisterGroupsToBuffer(buffer);
// }
//
SaveAVXTestDataToRegisterGroupsBuffer:
        push    %rbx
        mov     %rsi, %rbx    // rbx now holds buffer (arg1)
        call    load_ymm_registers
        mov     %rbx, %rdi
        pop     %rbx
        jmp     SaveRegisterGroupsToBuffer
        .size   SaveAVXTestDataToRegisterGroupsBuffer, .-SaveAVXTestDataToRegisterGroupsBuffer

        .globl  SaveAVX512TestDataToRegisterGroupsBuffer
        .type   SaveAVX512TestDataToRegisterGroupsBuffer, @function

// This is equivalent to:
//
// void SaveAVX512TestDataToRegisterGroupsBuffer(
//   const __m512* zmm, const uint64_t* opmask, bool opmask_is_64_bit,
//   RegisterGroupIOBuffer<X86_64>& buffeer); {
//   if (opmask_is_64_bit) {
//     load_opmask_registers_64(opmask);
//   } else {
//     load_opmask_registers_16(opmask);
//   }
//   load_zmm_registers(zmm);
//   SaveRegisterGroupsToBuffer(buffer);
// }
//
SaveAVX512TestDataToRegisterGroupsBuffer:
        push    %rbx
        mov     %rdi, %rbx  // save zmm
        push    %r12
        sub     $8, %rsp     // maintain 16-byte stack alignment for callees.
        mov     %rcx, %r12  // save buffer
        mov     %rsi, %rdi  // move ymm to arg1
        test    %dl, %dl    // check opmask_is_64_bit
        je      1f
        call    load_opmask_registers_64
        jmp     2f
1:
        call    load_opmask_registers_16
2:
        mov     %rbx, %rdi  // move zmm to arg1
        call    load_zmm_registers

        mov     %r12, %rdi  // move buffer to arg1
        add     $8, %rsp
        pop     %r12
        pop     %rbx
        jmp     SaveRegisterGroupsToBuffer
        .size   SaveAVX512TestDataToRegisterGroupsBuffer, .-SaveAVX512TestDataToRegisterGroupsBuffer

        .section        .note.GNU-stack,"",@progbits
