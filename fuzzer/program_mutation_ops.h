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

// Insert a randomly generated instruction at a random boundary in the program.
// Returns `true` if successful, returns `false` if the the random number
// generator was deeply unlucky.
bool InsertRandomInstruction(MutatorRng& rng, Program& program);

// Randomly modify a random instruction in the program.
// Returns `true` if successful, returns `false` if the the random number
// generator was unlucky, although some instructions may be more difficult to
// successfully mutate than others.
bool MutateRandomInstruction(MutatorRng& rng, Program& program);

// Remove a random instruction from the program.
// Returns `true` if successful, returns `false` if the program contains no
// instructions.
bool RemoveRandomInstruction(MutatorRng& rng, Program& program);

// Remove instructions until `program.NumBytes()` <= `max_len`.
// Returns `true` if the program was modified.
bool LimitProgramLength(MutatorRng& rng, Program& program, size_t max_len);

// Exported for testing
void FlipBit(uint8_t* buffer, size_t bit);
void FlipRandomBit(MutatorRng& rng, uint8_t* buffer, size_t buffer_size);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_PROGRAM_MUTATION_OPS_H_
