// Copyright 2025 The SiliFuzz Authors.
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

// This function translates the X86 XState register from an XSAVE area into a
// RegisterGroupIOBuffer with the following steps:
// 1. XSAVE host state to the `tmp_buffer`
// 2. XRSTOR the source xstate from the `src_buffer` to the host
// 3. Call SaveRegisterGroupsToBuffer() to save the host's XState to the `dest_buffer`
// 4. recover host's xstate from the `tmp_buffer`
// Note that XSAVE and XRSTOR require the operand to be 64-byte aligned.

        .text

        .p2align  4
        .globl    SaveX86XState
        .type     SaveX86XState, @function
SaveX86XState:

        push      %rbp
        mov       %rsp, %rbp

        // Save callee-saved registers.
        push      %rbx
        push      %r12
        push      %r13

        // move arguments to perserved registers
        mov       %rdi, %rbx  // rbx now holds 'src_buffer'
        mov       %rsi, %r12  // r12 now holds 'tmp_buffer'
        mov       %rdx, %r13  // r13 now holds 'dest_buffer'

        // XSAVE and XRSTOR below take an implicit operant EDX:EAX that is a
        // bitmask enumerates the xstate components that we want to save. Bits
        // will be ignored on machines that do not support them.
        //
        // The bitmask used here is 0b1110'0111:
        // Bit 0 - X87 state
        // Bit 1 - SSE state
        // Bit 2 - AVX state
        // Bit 7:5 - AVX512 state

        // 1. XSAVE original host state
        mov       $0xe7, %eax
        mov       $0, %edx
        xsave64   (%r12)

        // 2. XRSTOR the source xstate to the host
        xrstor64  (%rbx)

        // 3. save xstate to `dest_buffer`
        mov       %r13, %rdi
        call      SaveRegisterGroupsToBuffer

        // 4. recover original host's xstate
        mov       %ebx, %eax
        mov       %rbx, %rdx
        shrq      $32, %rdx
        xrstor64  (%r12)

        // Restore callee-saved registers and return.
        pop       %r13
        pop       %r12
        pop       %rbx
        pop       %rbp
        ret

        .size     SaveX86XState, .-SaveX86XState
        .section  .note.GNU-stack,"",@progbits
