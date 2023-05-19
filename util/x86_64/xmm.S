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

// Utility functions for handling SSE registers. These only use SSE
// instructions. We do not use instructions in higher SSE extension levels like
// SSE2 or SSE3.  The functions only deal with xmm registers accessing by
// SSE instructions. Registers xmm16 - xmm31 are parts of AVX512 state and
// are not supported here.

        .text

// Load xmm0-xmm15 from address in %rdi. The address must be 16-byte aligned.
        .p2align 4
        .globl  load_xmm_registers
        .type   load_xmm_registers, @function
load_xmm_registers:
#define LOAD_XMM(n) \
        movaps  n * 0x10(%rdi), %xmm ## n

        LOAD_XMM(0)
        LOAD_XMM(1)
        LOAD_XMM(2)
        LOAD_XMM(3)
        LOAD_XMM(4)
        LOAD_XMM(5)
        LOAD_XMM(6)
        LOAD_XMM(7)
        LOAD_XMM(8)
        LOAD_XMM(9)
        LOAD_XMM(10)
        LOAD_XMM(11)
        LOAD_XMM(12)
        LOAD_XMM(13)
        LOAD_XMM(14)
        LOAD_XMM(15)

#undef  LOAD_XMM
        ret
        .size   load_xmm_registers, .-load_xmm_registers

// Save xmm0-xmm15 to address in %rdi. The address must be 16-byte aligned.
        .p2align 4
        .globl  save_xmm_registers
        .type   save_xmm_registers, @function
save_xmm_registers:
#define SAVE_XMM(n) \
        movaps  %xmm ## n, n * 0x10(%rdi)

        SAVE_XMM(0)
        SAVE_XMM(1)
        SAVE_XMM(2)
        SAVE_XMM(3)
        SAVE_XMM(4)
        SAVE_XMM(5)
        SAVE_XMM(6)
        SAVE_XMM(7)
        SAVE_XMM(8)
        SAVE_XMM(9)
        SAVE_XMM(10)
        SAVE_XMM(11)
        SAVE_XMM(12)
        SAVE_XMM(13)
        SAVE_XMM(14)
        SAVE_XMM(15)

#undef  SAVE_XMM
        ret
        .size   save_xmm_registers, .-save_xmm_registers

// Clear xmm0-xmm15 to zeros.
        .p2align 4
        .globl  clear_xmm_registers
        .type   clear_xmm_registers, @function
clear_xmm_registers:
 #define CLEAR_XMM(n) \
        xorps   %xmm ## n, %xmm ## n

        CLEAR_XMM(0)
        CLEAR_XMM(1)
        CLEAR_XMM(2)
        CLEAR_XMM(3)
        CLEAR_XMM(4)
        CLEAR_XMM(5)
        CLEAR_XMM(6)
        CLEAR_XMM(7)
        CLEAR_XMM(8)
        CLEAR_XMM(9)
        CLEAR_XMM(10)
        CLEAR_XMM(11)
        CLEAR_XMM(12)
        CLEAR_XMM(13)
        CLEAR_XMM(14)
        CLEAR_XMM(15)

#undef CLEAR_XMM
        ret
        .size   clear_xmm_registers, .-clear_xmm_registers
