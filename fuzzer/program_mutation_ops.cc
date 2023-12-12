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

#include "./fuzzer/program_mutation_ops.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <random>

#include "absl/log/check.h"
#include "./fuzzer/program.h"
#include "./fuzzer/program_arch.h"

namespace silifuzz {

namespace {

template <int N>
void RandomizeBuffer(MutatorRng& rng, uint8_t (&buffer)[N]) {
  using ResultType = MutatorRng::result_type;

  static_assert(MutatorRng::min() == std::numeric_limits<ResultType>::min(),
                "RNG is expected to produce the full range of values.");
  static_assert(MutatorRng::max() == std::numeric_limits<ResultType>::max(),
                "RNG is expected to produce the full range of values.");

  static_assert(sizeof(buffer) % sizeof(ResultType) == 0,
                "Byte buffer should be a multiple of the RNG width.");

  ResultType* word_view = reinterpret_cast<ResultType*>(buffer);
  for (size_t i = 0; i < sizeof(buffer) / sizeof(ResultType); ++i) {
    *word_view++ = rng();
  }
}

void CopyOrRandomizeInstructionDisplacementBoundary(
    MutatorRng& rng, const InstructionDisplacementInfo& original,
    InstructionDisplacementInfo& mutated, size_t num_boundaries) {
  // Does this displacement need fixup?
  if (mutated.valid()) {
    if (original.valid() && mutated.encoded_byte_displacement ==
                                original.encoded_byte_displacement) {
      // Since the byte displacement is unchanged, preserve the boundary.
      // The boundary may be out of sync with the encoded byte displacement,
      // so we don't worry about the exact value of the byte displacement,
      // we're only observing that the mutation did not change it.
      mutated.instruction_boundary = original.instruction_boundary;
    } else {
      // If this was a newly discovered displacement, randomize the boundary.
      // If the displacement was mutated, randomize the boundary.
      // Trying to derive the boundary from the mutated displacement has a
      // number of pitfalls that we avoid with a complete re-randomization.
      RandomizeInstructionDisplacementBoundary(rng, mutated, num_boundaries);
    }
  }
}

// This function tries to determine which instruction each displacement of a
// newly mutated instruction should point to.
// 1) If the old instruction has the same kind of displacement (they are both
// direct branches, for example) and the byte displacement has not changed (the
// mutator did not touch the encoded displacement value) then copy the
// instruction index from the old instruction to the new instruction.
// 2) If the byte displacement was touched by the mutator, then randomize the
// instruction index. The encoded byte displacement may be out of sync with the
// symbolic instruction index, so we can't reason how the mutation affected the
// index - just assume that any mutation randomizes the index. Even if the
// encoding was kept in sync with the index, a mutation could result in a byte
// displacement that didn't point to a valid instruction boundary and we'd need
// to figure out how to fix this up in an unbiased way. In general, it's simpler
// to completely randomize the displacement when it is touched.
// 3) If the new instruction has a displacement but the old instruction does
// not, then randomize the displacement. Newly discovered displacements should
// be both random and valid.
void CopyOrRandomizeInstructionDisplacementBoundaries(
    MutatorRng& rng, const Instruction& original, Instruction& mutated,
    size_t num_boundaries) {
  CopyOrRandomizeInstructionDisplacementBoundary(
      rng, original.direct_branch, mutated.direct_branch, num_boundaries);
}

bool MutateInstruction(MutatorRng& rng, const Instruction& original,
                       Instruction& mutated) {
  uint8_t bytes[kInsnBufferSize];
  size_t num_old_bytes = original.encoded.size();

  // Individual mutations may not be successful. In some parts of the encoding
  // space it may be more difficult to mutate than others. Retry the mutation a
  // finite number of times so that callers of this function can assume that it
  // almost always succeeds.
  // In theory this could be an infinite loop, but it's implemented as a finite
  // loop to limit the worst case behavior.
  for (size_t i = 0; i < 64; ++i) {
    // Randomize the buffer - a mutation could cause the instruction to become
    // larger so we need to randomize the bytes after the instruction.
    // It's simpler/faster to randomize the whole buffer since we generate
    // random bytes in parallel.
    RandomizeBuffer(rng, bytes);

    // Copy in the original bytes.
    memcpy(bytes, original.encoded.data(), num_old_bytes);

    // Keep trying to mutate until we hit a valid instruction.
    // This lets us "push through" sparse parts of the encoding space.
    // We don't want to mutate too much, however, because at some point it
    // stops being a mutation and starts being a new random instruction.
    // This implementation is a bit ad-hoc and could use some experimentation
    // and tunning for the constants, etc.
    for (size_t j = 0; j < 3; ++j) {
      // TODO(ncbray): other mutation modes. Randomize byte, swap bytes, etc.
      FlipRandomBit(rng, bytes, num_old_bytes);
      if (InstructionFromBytes(bytes, sizeof(bytes), mutated)) {
        return true;
      }
    }
  }
  return false;
}

}  // namespace

bool GenerateRandomInstruction(MutatorRng& rng, Instruction& instruction) {
  uint8_t bytes[kInsnBufferSize];
  // It may take us a few tries to find a random set of bytes that decompile.
  // In theory this could be an infinite loop, but it's implemented as a finite
  // loop to limit the worst case behavior.
  for (size_t i = 0; i < 64; ++i) {
    RandomizeBuffer(rng, bytes);
    if (InstructionFromBytes(bytes, sizeof(bytes), instruction)) return true;
  }
  return false;
}

bool InsertRandomInstruction(MutatorRng& rng, Program& program) {
  Instruction insn;
  bool success = GenerateRandomInstruction(rng, insn);
  if (!success) return false;

  // Inserting the instruction will increase the number of potential instruction
  // boundaries by one.
  RandomizeInstructionDisplacementBoundaries(
      rng, insn, program.NumInstructionBoundaries() + 1);

  size_t insert_boundary = program.RandomInstructionBoundary(rng);
  bool steal_displacements = RandomIndex(rng, 2);
  program.InsertInstruction(insert_boundary, steal_displacements, insn);
  return true;
}

void FlipBit(uint8_t* buffer, size_t bit) {
  buffer[bit >> 3] ^= 1 << (bit & 0b111);
}

void FlipRandomBit(MutatorRng& rng, uint8_t* buffer, size_t buffer_size) {
  FlipBit(buffer, RandomIndex(rng, buffer_size * 8));
}

bool MutateRandomInstruction(MutatorRng& rng, Program& program) {
  // Is there anything to mutate?
  if (program.NumInstructions() == 0) return false;

  // Select a random instruction.
  size_t target = program.RandomInstructionIndex(rng);
  const Instruction& original = program.GetInstruction(target);

  Instruction mutated{};
  if (MutateInstruction(rng, original, mutated)) {
    CopyOrRandomizeInstructionDisplacementBoundaries(
        rng, original, mutated, program.NumInstructionBoundaries());
    program.SetInstruction(target, mutated);
    return true;
  }
  return false;
}

bool RemoveRandomInstruction(MutatorRng& rng, Program& program) {
  // Is there anything to remove?
  if (program.NumInstructions() == 0) return false;

  size_t victim = program.RandomInstructionIndex(rng);
  program.RemoveInstruction(victim);
  return true;
}

// Throw away instruction until we're under the length limit.
bool LimitProgramLength(MutatorRng& rng, Program& program, size_t max_len) {
  bool modified = false;
  while (program.ByteLen() > max_len) {
    CHECK_GT(program.NumInstructions(), 0);
    RemoveRandomInstruction(rng, program);
    modified = true;
  }
  return modified;
}

}  // namespace silifuzz
