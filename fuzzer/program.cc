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

#include "./fuzzer/program.h"

#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>
#include <random>
#include <vector>

#include "absl/log/check.h"
#include "absl/types/span.h"
#include "./fuzzer/program_arch.h"
#include "./util/arch.h"

namespace silifuzz {

template <typename Arch>
void InstructionData<Arch>::Copy(const uint8_t* bytes, size_t num_bytes) {
  CHECK_LE(num_bytes, sizeof(bytes_));
  memcpy(bytes_, bytes, num_bytes);
  num_bytes_ = num_bytes;
}

template class InstructionData<X86_64>;
template class InstructionData<AArch64>;

template struct Instruction<X86_64>;
template struct Instruction<AArch64>;

template <typename Arch>
void Program<Arch>::CheckConsistency() const {
  size_t actual_len = 0;
  for (const Instruction<Arch>& insn : instructions_) {
    if (insn.direct_branch.valid()) {
      CHECK_NE(insn.direct_branch.encoded_byte_displacement,
               kInvalidByteDisplacement);
      CHECK_NE(insn.direct_branch.instruction_boundary,
               kInvalidInstructionBoundary);
      CHECK_LT(insn.direct_branch.instruction_boundary,
               NumInstructionBoundaries());
    } else {
      CHECK_EQ(insn.direct_branch.encoded_byte_displacement,
               kInvalidByteDisplacement);
      CHECK_EQ(insn.direct_branch.instruction_boundary,
               kInvalidInstructionBoundary);
    }
    actual_len += insn.encoded.size();
  }
  CHECK_EQ(byte_len_, actual_len);
}

template <typename Arch>
void Program<Arch>::FixupInvariants() {
  uint64_t offset = 0;
  for (Instruction<Arch>& insn : instructions_) {
    insn.offset = offset;
    offset += insn.encoded.size();
  }
  byte_len_ = offset;
}

template <typename Arch>
size_t Program<Arch>::FindClosestInstructionBoundary(int64_t program_offset) {
  size_t closest_boundary = kInvalidInstructionBoundary;
  int64_t smallest_diff = std::numeric_limits<int64_t>::max();
  // TODO(ncbray): binary search
  for (size_t i = 0; i < NumInstructionBoundaries(); i++) {
    int64_t boundary_offset = InstructionBoundaryToProgramByteOffset(i);
    int64_t diff = std::abs(boundary_offset - program_offset);
    if (diff < smallest_diff) {
      smallest_diff = diff;
      closest_boundary = i;
    }
  }
  return closest_boundary;
}

template <typename Arch>
int64_t Program<Arch>::InstructionBoundaryToProgramByteOffset(
    size_t boundary) const {
  CHECK_LT(boundary, NumInstructionBoundaries());

  if (boundary < NumInstructions()) {
    return instructions_[boundary].offset;
  } else {
    // It's the end of the program.
    const Instruction<Arch>& insn = instructions_.back();
    return insn.offset + insn.encoded.size();
  }
}

template <typename Arch>
void Program<Arch>::ResolveDisplacements(bool strict) {
  for (Instruction<Arch>& insn : instructions_) {
    if (insn.direct_branch.valid() && insn.direct_branch.instruction_boundary ==
                                          kInvalidInstructionBoundary) {
      int64_t program_offset =
          insn.offset + insn.direct_branch.encoded_byte_displacement;
      size_t boundary = FindClosestInstructionBoundary(program_offset);
      if (strict) {
        CHECK_EQ(InstructionBoundaryToProgramByteOffset(boundary),
                 program_offset);
      }
      insn.direct_branch.instruction_boundary = boundary;
    }
  }
}

size_t RandomIndex(MutatorRng& rng, size_t size) {
  CHECK_GT(size, 0);
  return std::uniform_int_distribution<size_t>{0, size - 1}(rng);
}

void RandomizeInstructionDisplacementBoundary(MutatorRng& rng,
                                              InstructionDisplacementInfo& info,
                                              size_t num_boundaries) {
  if (info.valid()) {
    // Note: there is no guarantee this boundary can be successfully encoded.
    // We could add logic to only select instruction boundaries that can be
    // encoded, but this logic is somewhat subtle. Instead we can brute force
    // the problem by repeatedly re-randomizing. If this becomes a performance
    // bottleneck, we can implement a smarter approach.
    info.instruction_boundary = RandomIndex(rng, num_boundaries);
  }
}

template <typename Arch>
void RandomizeInstructionDisplacementBoundaries(MutatorRng& rng,
                                                Instruction<Arch>& insn,
                                                size_t num_boundaries) {
  if (insn.direct_branch.valid()) {
    RandomizeInstructionDisplacementBoundary(rng, insn.direct_branch,
                                             num_boundaries);
  }
}

template void RandomizeInstructionDisplacementBoundaries(
    MutatorRng& rng, Instruction<X86_64>& insn, size_t num_boundaries);
template void RandomizeInstructionDisplacementBoundaries(
    MutatorRng& rng, Instruction<AArch64>& insn, size_t num_boundaries);

template <typename Arch>
bool Program<Arch>::SyncByteDisplacement(const Instruction<Arch>& insn,
                                         InstructionDisplacementInfo& info) {
  if (!info.valid()) {
    // Nothing to sync.
    return false;
  }
  int64_t target_displacement =
      InstructionBoundaryToProgramByteOffset(info.instruction_boundary) -
      insn.offset;
  if (target_displacement == info.encoded_byte_displacement) {
    // Already in sync.
    return false;
  }
  // Sync required.
  info.encoded_byte_displacement = target_displacement;
  return true;
}

template <typename Arch>
bool Program<Arch>::SyncByteDisplacements(Instruction<Arch>& insn) {
  return SyncByteDisplacement(insn, insn.direct_branch);
}

template <typename Arch>
bool Program<Arch>::FixupEncodedDisplacements(MutatorRng& rng) {
  // Making sure the offsets are accurate before rewriting the branches.
  // When we rewrite the branches we also recalculate the offsets, but if we
  // make sure the offsets are up-to-date before we do the rewrite this saves
  // an iteration and possibly prevents unnecessary instruction canonicalization
  // due to rewriting.
  FixupInvariants();

  bool modified = false;

  // Rewriting instructions can change their size.
  // Changing their size can invalidate displacements.
  // Keep iterating until the size stabilizes.
  bool stable = false;
  size_t iteration = 0;
  while (!stable) {
    // Each instruction should only be canonicalized once, so in theory we
    // should never iterate more times that there are instructions plus one.
    CHECK_LE(iteration, NumInstructions());
    uint64_t offset = 0;
    stable = true;
    for (Instruction<Arch>& insn : instructions_) {
      // If an instruction offset has changed, we aren't stable.
      stable &= insn.offset == offset;
      insn.offset = offset;
      if (SyncByteDisplacements(insn)) {
        // The byte displacements changed, so we must rewrite the instruction.
        while (!TryToReencodeInstructionDisplacements(insn)) {
          // If the byte displacements can't be encoded into this
          // instruction, randomize the displacements and try again.
          RandomizeInstructionDisplacementBoundaries(
              rng, insn, NumInstructionBoundaries());
          SyncByteDisplacements(insn);
        }
        modified = true;
      }
      offset += insn.encoded.size();
    }
    // If the program size has changed, we aren't stable.
    // Note that this statement is effectively checking if the size of the last
    // instruction has changed, the prior loop will see all other size changes.
    stable &= byte_len_ == offset;
    byte_len_ = offset;
    iteration++;
  }

  encodings_may_be_invalid = false;
  return modified;
}

template <typename Arch>
Program<Arch>::Program() : byte_len_(0), encodings_may_be_invalid(false) {
  ArchSpecificInit<Arch>();
}

template <typename Arch>
Program<Arch>::Program(const uint8_t* bytes, size_t len,
                       const InstructionConfig& config, bool strict)
    : byte_len_(0), encodings_may_be_invalid(true) {
  ArchSpecificInit<Arch>();

  size_t offset = 0;
  while (offset < len) {
    Instruction<Arch> instruction;
    if (InstructionFromBytes(&bytes[offset], len - offset, instruction,
                             config)) {
      // Add the instruction.
      instruction.offset = offset;
      offset += instruction.encoded.size();
      instructions_.push_back(instruction);
    } else {
      CHECK(!strict);
      // Either the instruction did not decode or it was filtered out.
      size_t insn_len = instruction.encoded.size();
      if (insn_len == 0) {
        // Since the instruction did not decode we don't know how many bytes to
        // consume. Consume the smallest possible instruction - hopefully the
        // decoding will reconverge at some point.
        insn_len = kInstructionInfo<Arch>.min_size;
      }
      offset += insn_len;
    }
  }

  // We resolve displacements _before_ fixing up the offsets so that branches
  // are "as close as possible" in the case where we fail to decode all the
  // instructions. Fixing up offsets will squeeze out the "holes" between
  // instructions and make it hard to interpret the intent of the branches.
  ResolveDisplacements(strict);

  // Lay out the instructions one after each other.
  FixupInvariants();
}

template <typename Arch>
void Program<Arch>::SetInstructionBlock(
    size_t index, absl::Span<const Instruction<Arch>> insns) {
  CHECK_LE(index + insns.size(), NumInstructions());

  for (size_t i = 0; i < insns.size(); i++) {
    const Instruction<Arch>& insn = insns[i];

    // Keep the size in sync.
    byte_len_ -= instructions_[index + i].encoded.size();
    byte_len_ += insn.encoded.size();

    // Overwrite the instruction.
    instructions_[index + i] = insn;
  }

  // Displacements may require fixup.
  // Instruction size may have changed or the instruction itself may have
  // displacements that need to be re-encoded.
  encodings_may_be_invalid = true;
}

template <typename Arch>
void Program<Arch>::AdjustInstructionIndexes(size_t boundary, int64_t amount) {
  // When we do a stealing insert at the end of the program, we don't want
  // any of the instruction indexes to change. To support this we accept a
  // boundary that is slightly out of range. This means none of the indexes will
  // match and therefore nothing will change.
  CHECK_LE(boundary, NumInstructionBoundaries());
  for (Instruction<Arch>& insn : instructions_) {
    if (insn.direct_branch.valid()) {
      if (insn.direct_branch.instruction_boundary >= boundary) {
        insn.direct_branch.instruction_boundary += amount;
      }
    }
  }
}

template <typename Arch>
void Program<Arch>::InsertInstructionBlock(
    size_t boundary, bool steal_displacements,
    absl::Span<const Instruction<Arch>> insns) {
  CHECK_LT(boundary, NumInstructionBoundaries());

  // If we're stealing displacements, we want displacements targeting the
  // boundary we're inserting at to remain in place.
  // If we're not stealing displacements, displacements to the boundary we're
  // inserting at should be moved by the insert.
  size_t adjusted_offset = boundary;
  if (steal_displacements) adjusted_offset++;

  // Fix up the instruction indexes.
  AdjustInstructionIndexes(adjusted_offset, insns.size());

  // Insert the instruction.
  // Note the displacements and indexes for the new instruction may not have
  // been set, yet, so we insert after adjusting the indexes.
  for (const Instruction<Arch>& insn : insns) {
    byte_len_ += insn.encoded.size();
  }
  instructions_.insert(instructions_.begin() + boundary, insns.begin(),
                       insns.end());

  // Displacements may require fixup.
  encodings_may_be_invalid = true;

  // TODO(ncbray): Do we really need to stay in sync?
  FixupInvariants();
}

template <typename Arch>
void Program<Arch>::RemoveInstruction(size_t index) {
  CHECK_LT(index, NumInstructions());

  // Fix up the instruction indexes.
  // TODO(ncbray): does this add bias to the branch target? Randomize
  // displacements that reference the removed instruction to debias?
  AdjustInstructionIndexes(index + 1, -1);

  // Remove the instruction.
  byte_len_ -= instructions_[index].encoded.size();
  instructions_.erase(instructions_.begin() + index);

  // Displacements may require fixup.
  encodings_may_be_invalid = true;

  // TODO(ncbray): Do we really need to stay in sync?
  FixupInvariants();
}

template <typename Arch>
void Program<Arch>::ToBytes(std::vector<uint8_t>& output) const {
  CHECK(!encodings_may_be_invalid);
  output.clear();
  output.reserve(byte_len_);
  for (const Instruction<Arch>& insn : instructions_) {
    CHECK_EQ(insn.offset, output.size());
    output.insert(output.end(), insn.encoded.begin(), insn.encoded.end());
  }
}

template class Program<X86_64>;
template class Program<AArch64>;

}  // namespace silifuzz
