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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_PROGRAM_MUTATION_OPS_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_PROGRAM_MUTATION_OPS_H_

#include "./fuzzer/program.h"

namespace silifuzz {

// Try to generate a random instruction from scratch.
// Returns `true` is successful.
template <typename Arch>
bool GenerateRandomInstruction(MutatorRng& rng, Instruction<Arch>& instruction);

// Mutate `original` and place the output in `mutated` using the default
// single-instruction mutation policy.
// Returns `true` is successful.
template <typename Arch>
bool MutateInstruction(MutatorRng& rng, const Instruction<Arch>& original,
                       Instruction<Arch>& mutated);

// Assuming `original` is the original instruction and `mutated` is a modified
// copy, copy the instruction displacement boundaries if the encoded
// displacement is present in both `original` and `mutated` and did not change.
// Otherwise, randomize the boundaries that are present in `mutated` but not
// `original`, or were modified between the two versions.
template <typename Arch>
void CopyOrRandomizeInstructionDisplacementBoundaries(
    MutatorRng& rng, const Instruction<Arch>& original,
    Instruction<Arch>& mutated, size_t num_boundaries);

// Insert a randomly generated instruction at a random boundary in the program.
// Returns `true` if successful, returns `false` if the the random number
// generator was deeply unlucky.
template <typename Arch>
bool InsertRandomInstruction(MutatorRng& rng, Program<Arch>& program);

// Randomly modify a random instruction in the program.
// Returns `true` if successful, returns `false` if the the random number
// generator was unlucky, although some instructions may be more difficult to
// successfully mutate than others.
template <typename Arch>
bool MutateRandomInstruction(MutatorRng& rng, Program<Arch>& program);

// Remove a random instruction from the program.
// Returns `true` if successful, returns `false` if the program contains no
// instructions.
template <typename Arch>
bool RemoveRandomInstruction(MutatorRng& rng, Program<Arch>& program);

// Remove instructions until `program.NumBytes()` <= `max_len`.
// Returns `true` if the program was modified.
template <typename Arch>
bool LimitProgramLength(MutatorRng& rng, Program<Arch>& program,
                        size_t max_len);

// Exported for testing
void FlipBit(uint8_t* buffer, size_t bit);
void FlipRandomBit(MutatorRng& rng, uint8_t* buffer, size_t buffer_size);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_PROGRAM_MUTATION_OPS_H_
