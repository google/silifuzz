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

/* A simple implementation of _start on aarch64. */

        .text
        .p2align 4
        .globl  _start
        .type   _start, @function

_start:
        .cfi_startproc

/* Clear frame pointer and link register to terminate stack chain. */
        mov     x29, #0
        mov     x30, #0

/* Pass the raw stack pointer as an argument to _start_1. */
        mov     x0, sp

/*
 * Jump into higher-level code.
 * Unlike x86_64 we use a normal branch that does not save the return address.
 * There's no point is saving the return address and this allows the stack chain
 * to cleanly terminate with null frame and link registers, rather than having a
 * link register that points back to a frame-less call site. On aarch64 jumps
 * and calls also behave more similarly than on x86_64 since they do not modify
 * the stack pointer.
 */
        b       _start_1@PLT

        .cfi_endproc
        .size   _start, .-_start
        .section        .note.GNU-stack,"",@progbits
