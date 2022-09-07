// Copyright 2022 The SiliFuzz Authors.
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

/* A simple implementation of _start on x86-64. */

        .text
        .p2align 4
        .globl  _start
        .type   _start, @function

/*
 * According to x86-64 ABI. A Linux process starts with the following
 * register values:
 *
 * %rbp is unspecified at process initialization time, but the user code should
 * mark the deepest stack frame by setting the frame pointer to zero.
 * %rsp holds the address of the byte with lowest address which is part of the
 * stack. It is guaranteed to be 16-byte aligned at process entry.
 * %rdx a function pointer that the application should register with atexit
 * (BA_OS).
 */

_start:
        .cfi_startproc

/* Clear frame pointer to terminate stack chain. */
        xorq    %rbp, %rbp

/* Pass the raw stack pointer as an argument to _start_1. */
        movq    %rsp, %rdi

/*
 * Handle rest of initialization in C++. This is actually a tail-call
 * but we use a call instruction here to keep %rsp properly aligned
 * for the callee.
 */
        call     _start_1@PLT

/* Unreachable. Loop forever in case _start_1() returns. */
        jmp     .
        .cfi_endproc
        .size   _start, .-_start
        .section        .note.GNU-stack,"",@progbits
