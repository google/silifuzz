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
#include <numeric>
#include <random>

#include "absl/log/check.h"
#include "./fuzzer/program.h"
#include "./fuzzer/program_arch.h"
#include "./util/arch.h"  // IWYU pragma: keep

namespace silifuzz {

namespace {

// Copied from bitops.h because there's no good place to put it, yet.
template <size_t N>
static constexpr auto BestIntType() {
  if constexpr (N % sizeof(uint64_t) == 0) {
    return uint64_t{};
  } else if constexpr (N % sizeof(uint32_t) == 0) {
    return uint32_t{};
  } else if constexpr (N % sizeof(uint16_t) == 0) {
    return uint16_t{};
  } else {
    return uint8_t{};
  }
}

template <size_t N>
void RandomizeBuffer(MutatorRng& rng, uint8_t (&buffer)[N]) {
  using ResultType = MutatorRng::result_type;

  static_assert(MutatorRng::min() == std::numeric_limits<ResultType>::min(),
                "RNG is expected to produce the full range of values.");
  static_assert(MutatorRng::max() == std::numeric_limits<ResultType>::max(),
                "RNG is expected to produce the full range of values.");

  // Determine the largest integral type that is a multiple of the buffer size
  // as well as the RNG result size.
  using Granularity = decltype(BestIntType<std::gcd(N, sizeof(ResultType))>());

  static_assert(sizeof(buffer) % sizeof(Granularity) == 0,
                "Byte buffer should be a multiple of granularity.");
  static_assert(sizeof(ResultType) % sizeof(Granularity) == 0,
                "ResultType should be a multiple of granularity.");

  Granularity* word_view = reinterpret_cast<Granularity*>(buffer);
  for (size_t i = 0; i < sizeof(buffer) / sizeof(Granularity); ++i) {
    *word_view++ = (Granularity)rng();
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

void ShiftOrRandomizeInstructionDisplacementBoundary(
    MutatorRng& rng, InstructionDisplacementInfo& info, int64_t index_offset,
    size_t num_boundaries) {
  if (info.valid()) {
    int64_t shifted = (int64_t)info.instruction_boundary + index_offset;
    // If the shifted value is out of bounds, randomize it.
    if (shifted < 0 || shifted >= num_boundaries) {
      shifted = RandomIndex(rng, num_boundaries);
    }
    info.instruction_boundary = (size_t)shifted;
  }
}

}  // namespace

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
template <typename Arch>
void CopyOrRandomizeInstructionDisplacementBoundaries(
    MutatorRng& rng, const Instruction<Arch>& original,
    Instruction<Arch>& mutated, size_t num_boundaries) {
  CopyOrRandomizeInstructionDisplacementBoundary(
      rng, original.direct_branch, mutated.direct_branch, num_boundaries);
}

template void CopyOrRandomizeInstructionDisplacementBoundaries(
    MutatorRng& rng, const Instruction<X86_64>& original,
    Instruction<X86_64>& mutated, size_t num_boundaries);
template void CopyOrRandomizeInstructionDisplacementBoundaries(
    MutatorRng& rng, const Instruction<AArch64>& original,
    Instruction<AArch64>& mutated, size_t num_boundaries);

template <typename Arch>
void ShiftOrRandomizeInstructionDisplacementBoundaries(
    MutatorRng& rng, Instruction<Arch>& instruction, int64_t index_offset,
    size_t num_boundaries) {
  ShiftOrRandomizeInstructionDisplacementBoundary(
      rng, instruction.direct_branch, index_offset, num_boundaries);
}

template void ShiftOrRandomizeInstructionDisplacementBoundaries(
    MutatorRng& rng, Instruction<X86_64>& instruction, int64_t index_offset,
    size_t num_boundaries);
template void ShiftOrRandomizeInstructionDisplacementBoundaries(
    MutatorRng& rng, Instruction<AArch64>& instruction, int64_t index_offset,
    size_t num_boundaries);

template <typename Arch>
bool MutateSingleInstruction(MutatorRng& rng, const Instruction<Arch>& original,
                             Instruction<Arch>& mutated) {
  InstructionByteBuffer<Arch> bytes;
  size_t num_old_bytes = original.encoded.size();

  // Individual mutations may not be successful. In some parts of the encoding
  // space it may be more difficult to mutate than others. Retry the mutation a
  // finite number of times so that callers of this function can assume that it
  // almost always succeeds.
  // In theory this could be an infinite loop, but it's implemented as a finite
  // loop to limit the worst case behavior.
  for (size_t i = 0; i < 64; ++i) {
    if constexpr (kInstructionInfo<Arch>.max_size !=
                  kInstructionInfo<Arch>.min_size) {
      // Randomize the buffer - a mutation could cause the instruction to become
      // larger so we need to randomize the bytes after the instruction.
      // It's simpler/faster to randomize the whole buffer since we generate
      // random bytes in parallel.
      RandomizeBuffer(rng, bytes);
    }

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

template bool MutateSingleInstruction(MutatorRng& rng,
                                      const Instruction<X86_64>& original,
                                      Instruction<X86_64>& mutated);
template bool MutateSingleInstruction(MutatorRng& rng,
                                      const Instruction<AArch64>& original,
                                      Instruction<AArch64>& mutated);

template <typename Arch>
bool GenerateSingleInstruction(MutatorRng& rng,
                               Instruction<Arch>& instruction) {
  InstructionByteBuffer<Arch> bytes;
  // It may take us a few tries to find a random set of bytes that decompile.
  // In theory this could be an infinite loop, but it's implemented as a finite
  // loop to limit the worst case behavior.
  for (size_t i = 0; i < 64; ++i) {
    RandomizeBuffer(rng, bytes);
    if (InstructionFromBytes(bytes, sizeof(bytes), instruction)) return true;
  }
  return false;
}

template bool GenerateSingleInstruction(MutatorRng& rng,
                                        Instruction<X86_64>& instruction);
template bool GenerateSingleInstruction(MutatorRng& rng,
                                        Instruction<AArch64>& instruction);

void FlipBit(uint8_t* buffer, size_t bit) {
  buffer[bit >> 3] ^= 1 << (bit & 0b111);
}

void FlipRandomBit(MutatorRng& rng, uint8_t* buffer, size_t buffer_size) {
  FlipBit(buffer, RandomIndex(rng, buffer_size * 8));
}

// Throw away instruction until we're under the length limit.
template <typename Arch>
bool LimitProgramLength(MutatorRng& rng, Program<Arch>& program,
                        size_t max_len) {
  bool modified = false;
  DeleteInstruction<Arch> m;
  while (program.ByteLen() > max_len) {
    CHECK_GT(program.NumInstructions(), 0);
    m.Mutate(rng, program, program);
    modified = true;
  }
  return modified;
}

template bool LimitProgramLength(MutatorRng& rng, Program<X86_64>& program,
                                 size_t max_len);
template bool LimitProgramLength(MutatorRng& rng, Program<AArch64>& program,
                                 size_t max_len);

}  // namespace silifuzz
