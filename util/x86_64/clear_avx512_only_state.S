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

#ifdef __x86_64__
        .text
        .p2align 4
        .globl ClearAVX512OnlyState
        .type ClearAVX512OnlyState, @function

/*
 * Clears AVX-512 only state. This includes zmm16-zmm31 and k0-k7.
 * The upper parts of zmm0-zmm15 are also AVX-512 only but they can
 * be cleared using the AVX vzeroupper instruction elsewhere.
 *
 * This has to be done using assembly to ensure only the AVX-512 registers
 * intended to be cleared are written. Sanitizers inserts hooks in a C++
 * implement that clobbers additional registers behind our backs. Thus this
 * cannot be done in C++.
 */
ClearAVX512OnlyState:
        /* Clear zmm16-zmm31. */
        vpxorq  %zmm16, %zmm16, %zmm16
        vpxorq  %zmm17, %zmm17, %zmm17
        vpxorq  %zmm18, %zmm18, %zmm18
        vpxorq  %zmm19, %zmm19, %zmm19
        vpxorq  %zmm20, %zmm20, %zmm20
        vpxorq  %zmm21, %zmm21, %zmm21
        vpxorq  %zmm22, %zmm22, %zmm22
        vpxorq  %zmm23, %zmm23, %zmm23
        vpxorq  %zmm24, %zmm24, %zmm24
        vpxorq  %zmm25, %zmm25, %zmm25
        vpxorq  %zmm26, %zmm26, %zmm26
        vpxorq  %zmm27, %zmm27, %zmm27
        vpxorq  %zmm28, %zmm28, %zmm28
        vpxorq  %zmm29, %zmm29, %zmm29
        vpxorq  %zmm30, %zmm30, %zmm30
        vpxorq  %zmm31, %zmm31, %zmm31

        /* Clear opmask registers k0-k7. */
        kxorq %k0, %k0, %k0
        kxorq %k1, %k1, %k1
        kxorq %k2, %k2, %k2
        kxorq %k3, %k3, %k3
        kxorq %k4, %k4, %k4
        kxorq %k5, %k5, %k5
        kxorq %k6, %k6, %k6
        kxorq %k7, %k7, %k7
        retq

        .size ClearAVX512OnlyState, . - ClearAVX512OnlyState

        /* We do not need executable stack.  */
        .section        .note.GNU-stack,"",@progbits
#endif  // __x86_64__
