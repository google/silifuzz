// Copyright 2024 The SiliFuzz Authors.
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

// Bulk access (reading, writing, clearing) functions for various AArch64
// extension registers. These are low level functions for saving and restoring
// execution context.
//
// They are intended to be called from assembly because calling conventions will
// not prevent clobbering of most of the SVE registers.
#ifndef THIRD_PARTY_SILIFUZZ_UTIL_AARCH64_EXTENSION_REGISTERS_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_AARCH64_EXTENSION_REGISTERS_H_

#include <stdint.h>

namespace silifuzz {

// These functions are in "C" namespace so that they are easily callable by
// assembly callers without name-mangling.
extern "C" {

// SVE registers can vary in length. The provided buffer must be large enough to
// accommodate the length of registers on the current architecture.
//
// If the buffer is larger than the size occupied by the registers, it is up to
// the caller to properly clear/handle the unused section of the buffer to
// prevent confusion.

// ========== Z (vector) register functions ==========
// Loads z0-z31 from the buffer.
void LoadZRegisters(const uint8_t *buffer);
// Saves z0-z31 to the buffer.
void StoreZRegisters(uint8_t *buffer);
// Clears z0-z31 to zero.
void ClearZRegisters();

// ========== P (predicate) register functions ==========
// Loads p0-p15 from the buffer.
void LoadPRegisters(const uint8_t *buffer);
// Saves p0-p15 to the buffer.
void StorePRegisters(uint8_t *buffer);
// Clears p0-p15 to zero.
void ClearPRegisters();

// ========== FFR (first fault) register functions ==========
// Loads ffr from the buffer.
// Warning: This clobbers the p0 register.
void LoadFfrRegister(const uint8_t *buffer);
// Saves ffr to the buffer.
// Warning: This clobbers the p0 register.
void StoreFfrRegister(uint8_t *buffer);
// Clears ffr to zero.
// Warning: This clobbers the p0 register.
void ClearFfrRegister();
}

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_AARCH64_EXTENSION_REGISTERS_H_
