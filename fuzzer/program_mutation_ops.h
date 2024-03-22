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

#include <cstddef>

#include "./fuzzer/program.h"
#include "./fuzzer/program_mutator.h"

namespace silifuzz {

// Try to generate a random instruction from scratch.
// Returns `true` is successful.
template <typename Arch>
bool GenerateSingleInstruction(MutatorRng& rng, Instruction<Arch>& instruction);

// Mutate `original` and place the output in `mutated` using the default
// single-instruction mutation policy.
// Returns `true` is successful.
template <typename Arch>
bool MutateSingleInstruction(MutatorRng& rng, const Instruction<Arch>& original,
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
template <typename Arch>
class InsertGeneratedInstruction : public ProgramMutator<Arch> {
 public:
  InsertGeneratedInstruction() {}

  // Returns `true` if successful, returns `false` if the the random number
  // generator was deeply unlucky.
  bool Mutate(MutatorRng& rng, Program<Arch>& program,
              const Program<Arch>& other) override {
    Instruction<Arch> insn;
    bool success = GenerateSingleInstruction(rng, insn);
    if (!success) return false;

    // Inserting the instruction will increase the number of potential
    // instruction boundaries by one.
    RandomizeInstructionDisplacementBoundaries(
        rng, insn, program.NumInstructionBoundaries() + 1);

    size_t insert_boundary = program.RandomInstructionBoundary(rng);
    bool steal_displacements = RandomIndex(rng, 2);
    program.InsertInstruction(insert_boundary, steal_displacements, insn);
    return true;
  }
};

// Randomly modify a random instruction in the program.
template <typename Arch>
class MutateInstruction : public ProgramMutator<Arch> {
 public:
  MutateInstruction() {}

  // Returns `true` if successful, returns `false` if the the random number
  // generator was unlucky, although some instructions may be more difficult to
  // successfully mutate than others.
  bool Mutate(MutatorRng& rng, Program<Arch>& program,
              const Program<Arch>& other) override {
    // Is there anything to mutate?
    if (program.NumInstructions() == 0) return false;

    // Select a random instruction.
    size_t target = program.RandomInstructionIndex(rng);
    const Instruction<Arch>& original = program.GetInstruction(target);

    // Try to mutate.
    Instruction<Arch> mutated{};
    if (MutateSingleInstruction(rng, original, mutated)) {
      CopyOrRandomizeInstructionDisplacementBoundaries(
          rng, original, mutated, program.NumInstructionBoundaries());
      program.SetInstruction(target, mutated);
      return true;
    }
    return false;
  }
};

// Remove a random instruction from the program.
template <typename Arch>
class DeleteInstruction : public ProgramMutator<Arch> {
 public:
  explicit DeleteInstruction(size_t minimum_instructions = 0)
      : minimum_instructions_(minimum_instructions) {}

  // Returns `true` if successful, returns `false` if the program is too small
  // and we should not delete any instructions.
  bool Mutate(MutatorRng& rng, Program<Arch>& program,
              const Program<Arch>& other) override {
    // Can an instruction be removed without going below the minimum?
    if (program.NumInstructions() <= minimum_instructions_) return false;

    // Remove a random instruction.
    size_t victim = program.RandomInstructionIndex(rng);
    program.RemoveInstruction(victim);
    return true;
  }

 private:
  size_t minimum_instructions_;
};

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
