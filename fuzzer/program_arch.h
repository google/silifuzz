// Copyright 2023 The Silifuzz Authors.
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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_PROGRAM_ARCH_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_PROGRAM_ARCH_H_

#include <cstddef>
#include <cstdint>

#include "./fuzzer/program.h"

namespace silifuzz {

// Initialize the disassembler if needed, etc.
template <typename Arch>
void ArchSpecificInit();

// Initialize `instruction` by decoding the data in `bytes`.
// May not consume all the data in `bytes`.
// Returns `true` if it looks like a valid instruction Silifuzz will accept.
// Returns `false` if decoding did not consume every byte and
// `must_decode_everything` is true.
// instruction.encoded.size() will be zero if the instruction did not decode.
// instruction.encoded.size() will be the size of the decoded instruction if it
// decodes, even if Silifuzz rejects the instruction (for example: syscall).
template <typename Arch>
bool InstructionFromBytes(const uint8_t* bytes, size_t num_bytes,
                          Instruction<Arch>& instruction,
                          bool must_decode_everything = false);

// Attempt to reencode the instruction bytes with the byte displacements implied
// by the instruction boundaries.
// This will not always succeed because some instructions do not allocate enough
// bits to encode every displacement. For example, some x86_64 branches can only
// encode signed, 8-bit displacements.
template <typename Arch>
bool TryToReencodeInstructionDisplacements(Instruction<Arch>& insn);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_PROGRAM_ARCH_H_
