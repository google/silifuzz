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

        .text

// The test helpers are implemented in assembly because we want very precise
// control of extension registers.  If they were written in C/C++, a compiler
// may generate code that accesses those registers behind our back.

// These functions uses different x86 ISA extensions.  A caller must check for
// specific extension support before calling any of the followings.

// Fill xmm registers with their indices in single precision.
#define FILL_XMM0_TO_XMM15_WITH_INDICES \
        xor      %eax, %eax ; \
        cvtsi2ss %eax, %xmm0 ; \
        inc      %eax ; \
        cvtsi2ss %eax, %xmm1 ; \
        inc      %eax ; \
        cvtsi2ss %eax, %xmm2 ; \
        inc      %eax ; \
        cvtsi2ss %eax, %xmm3 ; \
        inc      %eax ; \
        cvtsi2ss %eax, %xmm4 ; \
        inc      %eax ; \
        cvtsi2ss %eax, %xmm5 ; \
        inc      %eax ; \
        cvtsi2ss %eax, %xmm6 ; \
        inc      %eax ; \
        cvtsi2ss %eax, %xmm7 ; \
        inc      %eax ; \
        cvtsi2ss %eax, %xmm8 ; \
        inc      %eax ; \
        cvtsi2ss %eax, %xmm9 ; \
        inc      %eax ; \
        cvtsi2ss %eax, %xmm10 ; \
        inc      %eax ; \
        cvtsi2ss %eax, %xmm11 ; \
        inc      %eax ; \
        cvtsi2ss %eax, %xmm12 ; \
        inc      %eax ; \
        cvtsi2ss %eax, %xmm13 ; \
        inc      %eax ; \
        cvtsi2ss %eax, %xmm14 ; \
        inc      %eax ; \
        cvtsi2ss %eax, %xmm15

        .p2align 4
        .globl  XMMSaveTestHelper
        .type   XMMSaveTestHelper, @function
XMMSaveTestHelper:
        FILL_XMM0_TO_XMM15_WITH_INDICES
        jmp     save_xmm_registers
        .size   XMMSaveTestHelper, .-XMMSaveTestHelper

        .p2align 4
        .globl  YMMSaveTestHelper
        .type   YMMSaveTestHelper, @function
YMMSaveTestHelper:
        // xmm0-xmm15 overlap with the lowest halves of ymm0-ymm15.
        FILL_XMM0_TO_XMM15_WITH_INDICES

        // Clear top halves of ymm registers.
        vzeroupper

        jmp     save_ymm_registers
        .size   YMMSaveTestHelper, .-YMMSaveTestHelper

        .p2align 4
        .globl  ZMMSaveTestHelper
        .type   ZMMSaveTestHelper, @function
ZMMSaveTestHelper:
        // xmm0-xmm15 overlap with the lowest quarters of zmm0-zmm15.
        FILL_XMM0_TO_XMM15_WITH_INDICES

        // Clear top part of zmm0-zmm15 registers.
        vzeroupper

        // Synthesize zmm16-zmm31 using addition.
        vaddps  %zmm15, %zmm1, %zmm16
        vaddps  %zmm16, %zmm1, %zmm17
        vaddps  %zmm17, %zmm1, %zmm18
        vaddps  %zmm18, %zmm1, %zmm19
        vaddps  %zmm19, %zmm1, %zmm20
        vaddps  %zmm20, %zmm1, %zmm21
        vaddps  %zmm21, %zmm1, %zmm22
        vaddps  %zmm22, %zmm1, %zmm23
        vaddps  %zmm23, %zmm1, %zmm24
        vaddps  %zmm24, %zmm1, %zmm25
        vaddps  %zmm25, %zmm1, %zmm26
        vaddps  %zmm26, %zmm1, %zmm27
        vaddps  %zmm27, %zmm1, %zmm28
        vaddps  %zmm28, %zmm1, %zmm29
        vaddps  %zmm29, %zmm1, %zmm30
        vaddps  %zmm30, %zmm1, %zmm31
        jmp     save_zmm_registers
        .size   ZMMSaveTestHelper, .-ZMMSaveTestHelper

        .p2align 4
        .globl  Opmask16SaveTestHelper
        .type   Opmask16SaveTestHelper, @function
Opmask16SaveTestHelper:
        // Fill opmask registers with their indices.
        xor     %eax, %eax
        kmovw   %eax, %k0
        inc     %eax
        kmovw   %eax, %k1
        inc     %eax
        kmovw   %eax, %k2
        inc     %eax
        kmovw   %eax, %k3
        inc     %eax
        kmovw   %eax, %k4
        inc     %eax
        kmovw   %eax, %k5
        inc     %eax
        kmovw   %eax, %k6
        inc     %eax
        kmovw   %eax, %k7
        jmp     save_opmask_registers_16
        .size   Opmask16SaveTestHelper, .-Opmask16SaveTestHelper

        .p2align 4
        .globl  Opmask64SaveTestHelper
        .type   Opmask64SaveTestHelper, @function
Opmask64SaveTestHelper:
        // Fill opmask registers with their indices.
        xor     %rax, %rax
        kmovq   %rax, %k0
        inc     %rax
        kmovq   %rax, %k1
        inc     %rax
        kmovq   %rax, %k2
        inc     %rax
        kmovq   %rax, %k3
        inc     %rax
        kmovq   %rax, %k4
        inc     %rax
        kmovq   %rax, %k5
        inc     %rax
        kmovq   %rax, %k6
        inc     %rax
        kmovq   %rax, %k7
        jmp     save_opmask_registers_64
        .size   Opmask64SaveTestHelper, .-Opmask64SaveTestHelper

#define ROUND_TRIP_TEST_HELPER(helper_name, load_function, save_function) \
        .p2align 4 ; \
        .globl  helper_name ; \
        .type   helper_name, @function ; \
helper_name: \
        push    %rbp ; \
        mov     %rsp,%rbp ;    /* save frame pointer */ \
        push    %rbx ; \
        push    %rax ;         /* to maintain 16-byte stack alignment. */ \
        mov     %rsi,%rbx ;    /* save arg-2 */ \
        call    load_function ; \
        mov     %rbx,%rdi ;    /* move arg-2 of self to arg-1 of tail call. */ \
        add     $0x8,%rsp ;    /* undo alignment padding. */ \
        pop     %rbx ; \
        pop     %rbp ; \
        jmp     save_function ;   /* tail call save register function */ \
        .size   helper_name, .-helper_name

ROUND_TRIP_TEST_HELPER(XMMRoundTripTestHelper, load_xmm_registers,
                       save_xmm_registers)
ROUND_TRIP_TEST_HELPER(YMMRoundTripTestHelper, load_ymm_registers,
                       save_ymm_registers)
ROUND_TRIP_TEST_HELPER(ZMMRoundTripTestHelper, load_zmm_registers,
                       save_zmm_registers)
ROUND_TRIP_TEST_HELPER(Opmask16RoundTripTestHelper, load_opmask_registers_16,
                       save_opmask_registers_16)
ROUND_TRIP_TEST_HELPER(Opmask64RoundTripTestHelper, load_opmask_registers_64,
                       save_opmask_registers_64)

#undef ROUND_TRIP_TEST_HELPER

#define CLEAR_TEST_HELPER(helper_name, load_function, clear_function, \
                          save_function) \
        .p2align 4 ; \
        .globl  helper_name ; \
        .type   helper_name, @function ; \
helper_name: \
        push    %rbp ; \
        mov     %rsp,%rbp ;    /* save frame pointer */ \
        push    %rbx ; \
        push    %rax ;         /* to maintain 16-byte stack alignment. */ \
        mov     %rsi,%rbx ;    /* save arg-2 */ \
        call    load_function ; \
        call    clear_function ; \
        mov     %rbx,%rdi ;    /* move arg-2 of self to arg-1 of tail call. */ \
        add     $0x8,%rsp ;    /* undo alignment padding. */ \
        pop     %rbx ; \
        pop     %rbp ; \
        jmp     save_function ;   /* tail call save register function */ \
        .size   helper_name, .-helper_name

CLEAR_TEST_HELPER(XMMClearTestHelper, load_xmm_registers,
                  clear_xmm_registers, save_xmm_registers)
CLEAR_TEST_HELPER(YMMClearTestHelper, load_ymm_registers,
                  clear_ymm_registers, save_ymm_registers)
CLEAR_TEST_HELPER(ZMMClearTestHelper, load_zmm_registers,
                  clear_zmm_registers, save_zmm_registers)
// There is only one version of clear_opmask_registers.
CLEAR_TEST_HELPER(Opmask16ClearTestHelper, load_opmask_registers_16,
                  clear_opmask_registers, save_opmask_registers_16)
CLEAR_TEST_HELPER(Opmask64ClearTestHelper, load_opmask_registers_64,
                  clear_opmask_registers, save_opmask_registers_64)

#undef CLEAR_TEST_HELPER
