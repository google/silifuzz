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
#include <cstdint>
#include <vector>

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

// Shift the instruction displacement boundaries of `instruction` so that the
// relative displacements are same after the instruction's index has shifted to
// index + `index_offset`. This is done by also shifting the displacements by
// `index_offset`.
// If keeping the new displacement no longer points to a valid instruction
// boundary, randomize the displacement to point to a valid boundary.
// This function is used when we want to copy one or more instructions from
// somewhere and we want to ensure the displacements of the copied instructions
// have the same relative shape when placed at their new location rather than
// preserving the absolute values.
template <typename Arch>
void ShiftOrRandomizeInstructionDisplacementBoundaries(
    MutatorRng& rng, Instruction<Arch>& instruction, int64_t index_offset,
    size_t num_boundaries);

template <typename Arch>
void ShiftOrRandomizeInstructionDisplacementBoundaries(
    MutatorRng& rng, std::vector<Instruction<Arch>>& block,
    int64_t index_offset, size_t num_boundaries) {
  for (Instruction<Arch>& instruction : block) {
    ShiftOrRandomizeInstructionDisplacementBoundaries(
        rng, instruction, index_offset, num_boundaries);
  }
}

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

template <typename Arch>
class SwapInstructions : public ProgramMutator<Arch> {
 public:
  SwapInstructions() {}

  bool Mutate(MutatorRng& rng, Program<Arch>& program,
              const Program<Arch>& other) override {
    // Need at least two instructions to swap.
    if (program.NumInstructions() < 2) return false;

    // Select the targets.
    size_t a = program.RandomInstructionIndex(rng);
    size_t b = program.RandomInstructionIndex(rng);
    while (a == b) {
      b = program.RandomInstructionIndex(rng);
    }

    // Copy the instructions.
    Instruction<Arch> a_instruction = program.GetInstruction(a);
    Instruction<Arch> b_instruction = program.GetInstruction(b);

    // Swap the instructions.
    // Note that the branch displacements are not affected by this operation.
    // A branch that is swapped will target the same absolute location.
    // An alternative mutation would be to move the displacement how ever much
    // the instruction moved and re-randomize it if it goes out of range.
    program.SetInstruction(a, b_instruction);
    program.SetInstruction(b, a_instruction);

    return true;
  }
};

// Copy a random chunk from the other program and insert it at a random
// instruction boundary.
template <typename Arch>
class CrossoverInsert : public ProgramMutator<Arch> {
 public:
  CrossoverInsert() {}

  bool Mutate(MutatorRng& rng, Program<Arch>& program,
              const Program<Arch>& other) override {
    // Is there anything to crossover with?
    if (other.NumInstructions() == 0) return false;

    // Determine how much of the other program we want to copy.
    // src_size = [1, NumInstructions()]
    size_t max_size = other.NumInstructions();
    size_t src_size = RandomIndex(rng, max_size) + 1;
    size_t src_index = RandomIndex(rng, other.NumInstructions() - src_size + 1);

    // We must copy because `program` and `other` can be aliased.
    std::vector<Instruction<Arch>> block =
        other.CopyInstructionBlock(src_index, src_size);

    // Determine where we want to insert the block.
    size_t dst_boundary = program.RandomInstructionBoundary(rng);

    // Fixup the branch displacements of the copied instructions.
    int64_t index_offset = (int64_t)dst_boundary - (int64_t)src_index;
    ShiftOrRandomizeInstructionDisplacementBoundaries(
        rng, block, index_offset,
        program.NumInstructionBoundaries() + block.size());

    // Insert.
    bool steal_displacements = RandomIndex(rng, 2);
    program.InsertInstructionBlock(dst_boundary, steal_displacements, block);
    return true;
  }
};

// Copy a random chunk from the other program and overwrite the current program
// at a random instruction idnex.
template <typename Arch>
class CrossoverOverwrite : public ProgramMutator<Arch> {
 public:
  CrossoverOverwrite() {}

  bool Mutate(MutatorRng& rng, Program<Arch>& program,
              const Program<Arch>& other) override {
    // Is there anything to overwrite?
    if (program.NumInstructions() == 0) return false;

    // Is there anything to crossover with?
    if (other.NumInstructions() == 0) return false;

    // Determine how much of the other program we want to copy.
    // We do not want to overwrite more than half the current program and cannot
    // copy more from the other program than exists.
    size_t max_size = std::min(std::max(1UL, program.NumInstructions() / 2),
                               other.NumInstructions());
    size_t src_size = RandomIndex(rng, max_size) + 1;
    size_t src_index = RandomIndex(rng, other.NumInstructions() - src_size + 1);

    // We must copy because `program` and `other` can be aliased.
    std::vector<Instruction<Arch>> block =
        other.CopyInstructionBlock(src_index, src_size);

    // Determine where we want to insert the block.
    size_t dst_index =
        RandomIndex(rng, program.NumInstructions() - block.size() + 1);

    // Fixup the branch displacements of the copied instructions.
    int64_t index_offset = (int64_t)dst_index - (int64_t)src_index;
    ShiftOrRandomizeInstructionDisplacementBoundaries(
        rng, block, index_offset, program.NumInstructionBoundaries());

    // Overwrite.
    program.SetInstructionBlock(dst_index, block);
    return true;
  }
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
