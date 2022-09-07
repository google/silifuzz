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
        .globl  SilifuzzAVXTestHelper
        .type SilifuzzAVXTestHelper, @function
//
// SilifuzzAVXTestHelper(__m512 zmm[32], uint16_t k[8], void (*func)());
//
// This function wraps 'func' for testing. It first loads all the AVX-512
// registers zmm0 to zmm31 from 'zmm[]' and all the mask registers k0 to k7 from
// 'k[]', then calls 'func' and finally writes back the registers to 'zmm[]' and
// 'k[]'.
//
// This is roughly equivalent to:
//
// SilifuzzAVXTestHelper(...) {
//   register _m512 zmm0 = zmm[0];
//   ...
//   register _m512 zmm31 = zmm[31];
//   register _mmask16 k0 = k[0];
//   ...
//   register _mmask16 k7 = k[7];
//   (*func)();
//   zmm[0] = zmm0;
//   ...
//   zmm[31] = zmm31;
//   k[0] = k0;
//   ...
//   k[7] = k7;
// }
//
// except that C++ code is compiled to saved and restore any live zmm and mask
// registers around the call to func to comply with the x86_64 ABI. The ABI says
// all live zmm and mask registers are saved by a caller.

SilifuzzAVXTestHelper:
        // Save the arguments
        pushq %rdi
        pushq %rsi

#define LOAD_ZMM(n)  vmovdqa64 n * 64(%rdi), %zmm##n

        // Load all AVX-512 registers.
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

// AVX-512F uses only the lowest 16 bits of a mask register. There are
// forms of kmov wider than 16-bit but they not AVX-512 foundation instruction.
#define LOAD_K(n) movzwl n * 2(%rsi), %eax ; kmovw %eax, %k##n

        // Load all masks.
        LOAD_K(0)
        LOAD_K(1)
        LOAD_K(2)
        LOAD_K(3)
        LOAD_K(4)
        LOAD_K(5)
        LOAD_K(6)
        LOAD_K(7)

        call *%rdx

        // Pop saved arguments since they are destoryed by call above.
        popq %rsi
        popq %rdi

#define STORE_ZMM(n)  vmovdqa64  %zmm##n, n * 64(%rdi)

        // Store all AVX-512 registers after call.
        STORE_ZMM(0)
        STORE_ZMM(1)
        STORE_ZMM(2)
        STORE_ZMM(3)
        STORE_ZMM(4)
        STORE_ZMM(5)
        STORE_ZMM(6)
        STORE_ZMM(7)
        STORE_ZMM(8)
        STORE_ZMM(9)
        STORE_ZMM(10)
        STORE_ZMM(11)
        STORE_ZMM(12)
        STORE_ZMM(13)
        STORE_ZMM(14)
        STORE_ZMM(15)
        STORE_ZMM(16)
        STORE_ZMM(17)
        STORE_ZMM(18)
        STORE_ZMM(19)
        STORE_ZMM(20)
        STORE_ZMM(21)
        STORE_ZMM(22)
        STORE_ZMM(23)
        STORE_ZMM(24)
        STORE_ZMM(25)
        STORE_ZMM(26)
        STORE_ZMM(27)
        STORE_ZMM(28)
        STORE_ZMM(29)
        STORE_ZMM(30)
        STORE_ZMM(31)

#define STORE_K(n) kmovw %k##n, %eax ; movw %ax, n * 2(%rsi)

        // Store all masks.
        STORE_K(0)
        STORE_K(1)
        STORE_K(2)
        STORE_K(3)
        STORE_K(4)
        STORE_K(5)
        STORE_K(6)
        STORE_K(7)

        ret

        .size SilifuzzAVXTestHelper, .-SilifuzzAVXTestHelper
        .section  .note.GNU-stack,"",@progbits
#endif  // __x86_64__
