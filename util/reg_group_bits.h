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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_REG_GROUP_BITS_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_REG_GROUP_BITS_H_

// This file defines a set of C preprocessor macros for representing register
// groups in different CPU architectures supported by SiliFuzz. The definitions
// are shared by C++ and assembly code. The bits are OR'ed together to form
// a set representation of register groups on a particular architecture. As
// we do not mix register groups of different architectures, bit positions are
// reused in different architectures.

// ------------------------ x86-64 register groups ---------------------------

// All GPRs and integer control registers like RFLAGS.
#define X86_REG_GROUP_GPR 0x1

// Legacy x87 stack, special registers and SSE registers. xmm0-xmm15 and mxcsr.
#define X86_REG_GROUP_FPR_AND_SSE 0x2

// ymm0-ymm15
#define X86_REG_GROUP_AVX 0x4

// zmm0-zmm31 and k0-k7
#define X86_REG_GROUP_AVX512 0x8

// AMX tile configuration and tiles.
#define X86_REG_GROUP_AMX 0x10

// ------------------------ AArch64 register groups --------------------------
#define AARCH64_REG_GROUP_GPR 0x1
#define AARCH64_REG_GROUP_FPR 0x2

// z0-z31, p0-p15, and ffr
#define AARCH64_REG_GROUP_SVE 0x4

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_REG_GROUP_BITS_H_
