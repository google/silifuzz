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

// Utility functions for handling AVX512 mask registers. AVX512F instructions
// only access the lowest 16 bits of each mask registers. AVx512BW instructions
// allow access up to the lowest 64 bits. Some functions below have two versions
// for both 16-bit and 64-bit accesses.

        .text

// Load opmask registers k0-k7 from address in %rdi as 8 16-bit words.
// The address must be word-aligned. Any upper opmask bits are cleared.
        .p2align 4
        .globl  load_opmask_registers_16
        .type   load_opmask_registers_16, @function
load_opmask_registers_16:
#define LOAD_OPMASK_16(n) \
        kmovw   n * 2(%rdi), %k ## n

        LOAD_OPMASK_16(0)
        LOAD_OPMASK_16(1)
        LOAD_OPMASK_16(2)
        LOAD_OPMASK_16(3)
        LOAD_OPMASK_16(4)
        LOAD_OPMASK_16(5)
        LOAD_OPMASK_16(6)
        LOAD_OPMASK_16(7)

#undef  LOAD_OPMASK_16
        ret
        .size   load_opmask_registers_16, .-load_opmask_registers_16

// Load opmask registers k0-k7 from address in %rdi as 8 64-bit qwords.
// The address must be qword-aligned.
        .p2align 4
        .globl  load_opmask_registers_64
        .type   load_opmask_registers_64, @function
load_opmask_registers_64:
#define LOAD_OPMASK_64(n) \
        kmovq   n * 8(%rdi), %k ## n

        LOAD_OPMASK_64(0)
        LOAD_OPMASK_64(1)
        LOAD_OPMASK_64(2)
        LOAD_OPMASK_64(3)
        LOAD_OPMASK_64(4)
        LOAD_OPMASK_64(5)
        LOAD_OPMASK_64(6)
        LOAD_OPMASK_64(7)

#undef  LOAD_OPMASK_64
        ret
        .size   load_opmask_registers_64, .-load_opmask_registers_64

// Save k0-k7 to address in %rdi as 8 16-bit words. The address must be
// word-aligned.
        .p2align 4
        .globl  save_opmask_registers_16
        .type   save_opmask_registers_16, @function
save_opmask_registers_16:
#define SAVE_OPMASK_16(n) \
        kmovw   %k ## n, n * 2(%rdi)

        SAVE_OPMASK_16(0)
        SAVE_OPMASK_16(1)
        SAVE_OPMASK_16(2)
        SAVE_OPMASK_16(3)
        SAVE_OPMASK_16(4)
        SAVE_OPMASK_16(5)
        SAVE_OPMASK_16(6)
        SAVE_OPMASK_16(7)

#undef  SAVE_OPMASK_16
        ret
        .size   save_opmask_registers_16, .-save_opmask_registers_16

// Save k0-k7 to address in %rdi as 8 64-bit qwords.  The address must be
// qword-aligned.
        .p2align 4
        .globl  save_opmask_registers_64
        .type   save_opmask_registers_64, @function
save_opmask_registers_64:
#define SAVE_OPMASK_64(n) \
        kmovq   %k ## n, n * 8(%rdi)

        SAVE_OPMASK_64(0)
        SAVE_OPMASK_64(1)
        SAVE_OPMASK_64(2)
        SAVE_OPMASK_64(3)
        SAVE_OPMASK_64(4)
        SAVE_OPMASK_64(5)
        SAVE_OPMASK_64(6)
        SAVE_OPMASK_64(7)

#undef  SAVE_OPMASK_64
        ret
        .size   save_opmask_registers_64, .-save_opmask_registers_64

// Clear opmask registers k0-k7. The kxorw instruction clears the upper
// bits so there are no separate versions for 16-bit and 64-bit register sizes.
        .p2align 4
        .globl  clear_opmask_registers
        .type   clear_opmask_registers, @function
clear_opmask_registers:
#define CLEAR_OPMASK(n) \
        kxorw   %k ## n, %k ## n, %k ## n

        CLEAR_OPMASK(0)
        CLEAR_OPMASK(1)
        CLEAR_OPMASK(2)
        CLEAR_OPMASK(3)
        CLEAR_OPMASK(4)
        CLEAR_OPMASK(5)
        CLEAR_OPMASK(6)
        CLEAR_OPMASK(7)

#undef CLEAR_OPMASK
        ret
        .size   clear_opmask_registers, .-clear_opmask_registers
