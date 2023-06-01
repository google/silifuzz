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

// Bulk access functions for various x86-64 extension registers.
// The functions provides reading, writing and clearing of various x86-64
// extension registers as groups. These are low level functions for saving
// and restoring execution context.
#ifndef THIRD_PARTY_SILIFUZZ_UTIL_X86_64_EXTENSION_REGISTERS_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_X86_64_EXTENSION_REGISTERS_H_
#include <x86intrin.h>

#include <cstdint>

// These functions are in "C" namespace so that they are easily callable by
// assembly callers without name-mangling.
extern "C" {

// ========== XMM register functions ==========
// These only use basic SSE instructions. These functions require bit edx[25]
// to be set by CPUID function 1.

// Loads SSE registers xmm0-xmm15. 'buffer' must be 16-byte aligned and have
// size of 256 bytes.
void load_xmm_registers(const __m128* buffer);

// Saves SSE registers xmm0-xmm15. 'buffer' must be 16-byte aligned and have
// size of 256 bytes.
void save_xmm_registers(__m128* buffer);

// Sets SSE registers xmm0-xmm15 to zeros.
void clear_xmm_registers();

// ========== YMM register functions ==========
// These only use basic AVX instructions. These functions require bit ecx[28]
// to be set by CPUID function 1.

// Loads AVX registers ymm0-ymm15. 'buffer' must be 32-byte aligned and have
// size of 512 bytes.
void load_ymm_registers(const __m256* buffer);

// Saves AVX registers ymm0-ymm15. 'buffer' must be 32-byte aligned and have
// size of 512 bytes.
void save_ymm_registers(__m256* buffer);

// Sets AVX registers ymm0-ymm15 to zeros.
void clear_ymm_registers();

// ========== ZMM register functions ==========
// These only use AVX-512F instructions. These functions require bit ebx[16] to
// be set by CPUID function 7.

// Loads AVX-512 registers zmm0-ymm31. 'buffer' must be 64-byte aligned and have
// a size 2 KiB.
void load_zmm_registers(const __m512* buffer);

// Saves AVX-512 registers zmm0-ymm31. 'buffer' must be 64-byte aligned nd have
// a size of 2 KiB.
void save_zmm_registers(__m512* buffer);

// Sets AVX-512 registers zmm0-zmm31 to zeros.
void clear_zmm_registers();

// ========== Opmask register functions ==========

// Loads AVX-512 opmask registers k0-k7. 'buffer' must be 64-bit aligned and
// have a size of 64 bytes. Upper 48 bits of each uint64_t in 'buffer' are
// ignored. Any opmask bits higher than 16 are cleared.
void load_opmask_registers_16(const uint64_t* buffer);

// Saves lowest 16 bits of AVX-512 opmask registers k0-k7 as 8 uint64_t.
// 'buffer' must be 64-bit aligned and have size of 64 bytes. Upper 48 bits
// of each uint64_t in 'buffer' are set to zeros.
void save_opmask_registers_16(uint64_t* buffer);

// Sets AVX-512 opmask registers k0-k7 to zeros.
void clear_opmask_registers();

// These use AVX-512BW instructions to access 64-bit opmasks.  These functions
// require bit ebx[30] to be set by CPUID function 7.

// Loads AVX-512 opmask registers k0-k7. 'buffer must be 64-bit aligned and have
// a size of 64 bytes. Any opmask bits higher than 64 are cleared.
void load_opmask_registers_64(const uint64_t* buffer);

// Saves lowest 64 bits of AVX-512 opmask registers k0-k7. 'buffer must be
// 64-bit aligned and have a size of 64 bytes.
void save_opmask_registers_64(uint64_t* buffer);

// TODO(dougkwan) add functions for AMX registers.
}

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_X86_64_EXTENSION_REGISTERS_H_
