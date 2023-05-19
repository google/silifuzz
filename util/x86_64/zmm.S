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

// Utility functions for handling AVX-512 registers. These only use AVX-512F
// instructions.

        .text

// Load zmm0-zmm31 from address in %rdi. The address must be 64-byte aligned.
        .p2align 4
        .globl   load_zmm_registers
        .type    load_zmm_registers, @function
load_zmm_registers:
#define LOAD_ZMM(n) \
        vmovdqa32       n * 0x40(%rdi), %zmm ## n

        LOAD_ZMM(0)
        LOAD_ZMM(1)
        LOAD_ZMM(2)
        LOAD_ZMM(3)
        LOAD_ZMM(4)
        LOAD_ZMM(5)
        LOAD_ZMM(6)
        LOAD_ZMM(7)
        LOAD_ZMM(8)
        LOAD_ZMM(9)
        LOAD_ZMM(10)
        LOAD_ZMM(11)
        LOAD_ZMM(12)
        LOAD_ZMM(13)
        LOAD_ZMM(14)
        LOAD_ZMM(15)
        LOAD_ZMM(16)
        LOAD_ZMM(17)
        LOAD_ZMM(18)
        LOAD_ZMM(19)
        LOAD_ZMM(20)
        LOAD_ZMM(21)
        LOAD_ZMM(22)
        LOAD_ZMM(23)
        LOAD_ZMM(24)
        LOAD_ZMM(25)
        LOAD_ZMM(26)
        LOAD_ZMM(27)
        LOAD_ZMM(28)
        LOAD_ZMM(29)
        LOAD_ZMM(30)
        LOAD_ZMM(31)

#undef  LOAD_ZMM
        ret
        .size    load_zmm_registers, .-load_zmm_registers

// Save zmm0-zmm31 to address in %rdi.  The address must be 64-byte aligned.
        .p2align 4
        .globl   save_zmm_registers
        .type    save_zmm_registers, @function
save_zmm_registers:
#define SAVE_ZMM(n) \
        vmovdqa32       %zmm ## n, n * 0x40(%rdi)

        SAVE_ZMM(0)
        SAVE_ZMM(1)
        SAVE_ZMM(2)
        SAVE_ZMM(3)
        SAVE_ZMM(4)
        SAVE_ZMM(5)
        SAVE_ZMM(6)
        SAVE_ZMM(7)
        SAVE_ZMM(8)
        SAVE_ZMM(9)
        SAVE_ZMM(10)
        SAVE_ZMM(11)
        SAVE_ZMM(12)
        SAVE_ZMM(13)
        SAVE_ZMM(14)
        SAVE_ZMM(15)
        SAVE_ZMM(16)
        SAVE_ZMM(17)
        SAVE_ZMM(18)
        SAVE_ZMM(19)
        SAVE_ZMM(20)
        SAVE_ZMM(21)
        SAVE_ZMM(22)
        SAVE_ZMM(23)
        SAVE_ZMM(24)
        SAVE_ZMM(25)
        SAVE_ZMM(26)
        SAVE_ZMM(27)
        SAVE_ZMM(28)
        SAVE_ZMM(29)
        SAVE_ZMM(30)
        SAVE_ZMM(31)

#undef  SAVE_ZMM
        ret
        .size    save_zmm_registers, .-save_zmm_registers

// Clear zmm0-zmm31 to zeros.
        .p2align 4
        .globl   clear_zmm_registers
        .type    clear_zmm_registers, @function
clear_zmm_registers:
#define CLEAR_ZMM(n) \
        vpxorq  %zmm ## n, %zmm ## n, %zmm ## n

        CLEAR_ZMM(0)
        CLEAR_ZMM(1)
        CLEAR_ZMM(2)
        CLEAR_ZMM(3)
        CLEAR_ZMM(4)
        CLEAR_ZMM(5)
        CLEAR_ZMM(6)
        CLEAR_ZMM(7)
        CLEAR_ZMM(8)
        CLEAR_ZMM(9)
        CLEAR_ZMM(10)
        CLEAR_ZMM(11)
        CLEAR_ZMM(12)
        CLEAR_ZMM(13)
        CLEAR_ZMM(14)
        CLEAR_ZMM(15)
        CLEAR_ZMM(16)
        CLEAR_ZMM(17)
        CLEAR_ZMM(18)
        CLEAR_ZMM(19)
        CLEAR_ZMM(20)
        CLEAR_ZMM(21)
        CLEAR_ZMM(22)
        CLEAR_ZMM(23)
        CLEAR_ZMM(24)
        CLEAR_ZMM(25)
        CLEAR_ZMM(26)
        CLEAR_ZMM(27)
        CLEAR_ZMM(28)
        CLEAR_ZMM(29)
        CLEAR_ZMM(30)
        CLEAR_ZMM(31)

#undef CLEAR_ZMM
        ret
        .size    clear_zmm_registers, .-clear_zmm_registers
