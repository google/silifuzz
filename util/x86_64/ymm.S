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

// Utility functions for handling AVX registers. These only use AVX
// instructions. We do not use instructions in higher SSE extension levels like
// AVX2.  The functions only deal with ymm registers accessing by AVX
// instructions. Registers ymm16 - ymm31 are parts of AVX512 state and are not
// supported here.

        .text

// Load ymm0-ymm15 from address in %rdi. The address must be 32-byte aligned.
        .p2align 4
        .globl  load_ymm_registers
        .type   load_ymm_registers, @function
load_ymm_registers:
#define LOAD_YMM(n) \
        vmovdqa n * 0x20(%rdi), %ymm ## n

        LOAD_YMM(0)
        LOAD_YMM(1)
        LOAD_YMM(2)
        LOAD_YMM(3)
        LOAD_YMM(4)
        LOAD_YMM(5)
        LOAD_YMM(6)
        LOAD_YMM(7)
        LOAD_YMM(8)
        LOAD_YMM(9)
        LOAD_YMM(10)
        LOAD_YMM(11)
        LOAD_YMM(12)
        LOAD_YMM(13)
        LOAD_YMM(14)
        LOAD_YMM(15)

#undef  LOAD_YMM
        ret
        .size   load_ymm_registers, .-load_ymm_registers

// Save ymm0-ymm15 to address in %rdi. The address must be 32-byte aligned.
        .p2align 4
        .globl  save_ymm_registers
        .type   save_ymm_registers, @function
save_ymm_registers:
#define SAVE_YMM(n) \
        vmovdqa  %ymm ## n, n * 0x20(%rdi)

        SAVE_YMM(0)
        SAVE_YMM(1)
        SAVE_YMM(2)
        SAVE_YMM(3)
        SAVE_YMM(4)
        SAVE_YMM(5)
        SAVE_YMM(6)
        SAVE_YMM(7)
        SAVE_YMM(8)
        SAVE_YMM(9)
        SAVE_YMM(10)
        SAVE_YMM(11)
        SAVE_YMM(12)
        SAVE_YMM(13)
        SAVE_YMM(14)
        SAVE_YMM(15)

#undef  SAVE_YMM
        ret
        .size   save_ymm_registers, .-save_ymm_registers

// Clear ymm0-ymm15 to zeros.
        .p2align 4
        .globl  clear_ymm_registers
        .type   clear_ymm_registers, @function
clear_ymm_registers:
#define CLEAR_YMM(n) \
        vpxor   %ymm ## n, %ymm ## n, %ymm ## n

        CLEAR_YMM(0)
        CLEAR_YMM(1)
        CLEAR_YMM(2)
        CLEAR_YMM(3)
        CLEAR_YMM(4)
        CLEAR_YMM(5)
        CLEAR_YMM(6)
        CLEAR_YMM(7)
        CLEAR_YMM(8)
        CLEAR_YMM(9)
        CLEAR_YMM(10)
        CLEAR_YMM(11)
        CLEAR_YMM(12)
        CLEAR_YMM(13)
        CLEAR_YMM(14)
        CLEAR_YMM(15)

#undef CLEAR_YMM
        ret
        .size   clear_ymm_registers, .-clear_ymm_registers
