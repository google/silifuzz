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

#include "./fuzzer/program_mutator.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <random>
#include <vector>

#include "./fuzzer/program.h"
#include "./fuzzer/program_mutation_ops.h"

namespace silifuzz {

namespace {

bool TrySingleMutation(MutatorRng& rng, Program& program) {
  // TODO(ncbray): swap instructions.
  // TODO(ncbray): copy instruction from other program.
  // TODO(ncbray): copy instruction from dictionary.
  // TODO(ncbray): crossover.

  // TODO(ncbray): how should these be weighted?
  std::discrete_distribution<> d({10, 10, 10});

  switch (d(rng)) {
    case 0:
      return InsertRandomInstruction(rng, program);
    case 1:
      return MutateRandomInstruction(rng, program);
    case 2:
      // TODO(ncbray): consider what the best policy is for randomly removing
      // instructions.
      // Removing instructions is tricky to get right.
      // In general we want to grow larger, non-trivial inputs.
      // On the other hand, we also want to aggressively garbage collect
      // "uninteresting" instructions to prevent them from being copied along
      // from input to input along with the interesting ones.
      // How we balance growth vs. garbage collection TBD.
      // For now, do not remove instructions if the program is small.
      // This avoid cases where we remove all the instructions in a program and
      // destroy 100% of the information the original input contained.
      if (program.NumInstructions() < 3) {
        return false;
      }
      return RemoveRandomInstruction(rng, program);
    default:
      return false;
  }
}

void ApplySingleMutation(MutatorRng& rng, Program& program) {
  // Mutation operations may fail, retry a few times until we succeed.
  for (size_t i = 0; i < 64; i++) {
    if (TrySingleMutation(rng, program)) {
      program.CheckConsistency();
      return;
    }
  }
}

// Centipede expects that mutators will never produce outputs that are zero
// bytes in length. Get out of this situation by adding random instructions.
void AddInstructionIfZeroLength(MutatorRng& rng, Program& program) {
  while (program.ByteLen() == 0) {
    InsertRandomInstruction(rng, program);
  }
}

void FinalizeProgram(MutatorRng& rng, Program& program, size_t max_len) {
  // Note that LimitProgramLength may reduce the program size back to zero.
  // We consider obeying max_len more important than outputting non-trivial
  // inputs.
  AddInstructionIfZeroLength(rng, program);

  // FixupEncodedDisplacements can change the program length.
  // LimitProgramLength can invalidate the displacements.
  // In most cases it should be safe to limit and then fixup.
  // We're doing the iterative approach because it's robust against fixup doing
  // something strange.
  // We limit the program length first, however, because it could help avoid the
  // need for more drastic fixups on out-of-range branches.
  LimitProgramLength(rng, program, max_len);
  while (true) {
    if (!program.FixupEncodedDisplacements(rng)) break;
    if (!LimitProgramLength(rng, program, max_len)) break;
  }
}

}  // namespace

void ProgramMutator::GenerateSingleOutput(const Program& input,
                                          std::vector<uint8_t>& output) {
  // Copy
  Program program = input;

  // Mutate
  size_t num_mutations = std::uniform_int_distribution<size_t>{1, 3}(rng_);
  for (size_t i = 0; i < num_mutations; ++i) {
    ApplySingleMutation(rng_, program);
  }

  // Output
  FinalizeProgram(rng_, program, max_len_);
  program.ToBytes(output);
}

void ProgramMutator::Mutate(
    const std::vector<const std::vector<uint8_t>*>& inputs, size_t num_mutants,
    std::vector<std::vector<uint8_t>>& mutants) {
  // Extract the programs from the inputs.
  // Copying a program should be cheaper that re-parsing each instruction for
  // each mutant.
  std::vector<Program> programs;
  programs.reserve(inputs.size());
  for (const std::vector<uint8_t>* input : inputs) {
    programs.push_back(Program(*input));
  }

  // Generate the requested mutants.
  for (size_t i = 0; i < num_mutants; ++i) {
    size_t base = RandomIndex(rng_, inputs.size());
    GenerateSingleOutput(programs[base], mutants[i]);
  }
}

}  // namespace silifuzz
