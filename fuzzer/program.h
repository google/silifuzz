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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_PROGRAM_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_PROGRAM_H_

#include <cstddef>
#include <cstdint>
#include <limits>
#include <random>
#include <vector>

namespace silifuzz {

// An alias for the Rng we're using.
using MutatorRng = std::mt19937_64;

// Return a random integer [0, `size`).
// `size` must be greater than zero.
size_t RandomIndex(MutatorRng& rng, size_t size);

// An out-of-range displacement value, to be used when the displacement does not
// exist.
constexpr int64_t kInvalidByteDisplacement =
    std::numeric_limits<int64_t>::max();

// An out-of-range instruction boundary, to be used when the boundary does not
// exist.
constexpr size_t kInvalidInstructionBoundary =
    std::numeric_limits<size_t>::max();

// Information about a PC-relative displacement contained in an instruction that
// points to another instruction.
struct InstructionDisplacementInfo {
  // The instruction displacement encoded inside this instruction, in bytes.
  // The value is relative to the start of the instruction.
  // This matches how aarch64 defines displacements.
  // x86_64 defines displacements as relative to the end of the instruction, but
  // we do that conversion in arch-specific code and leave this arch-neutral
  // value relative to the start of the instruction because it's simpler.
  int64_t encoded_byte_displacement = kInvalidByteDisplacement;

  // The instruction boundary the displacement should point to.
  // As instruction "instruction boundary" is a number in the range
  // [0, num_instructions] that either refers to the start of an instruction or
  // the end of the program.
  // Note that the instruction index can differ from the instruction pointed to
  // by the encoded byte displacement. The instruction index is considered to be
  // where the displacement _should_ be pointing, whereas the byte displacement
  // is where the encoded instruction _is_ pointing. We let these get out of
  // sync while mutating the program and fix up the encoded instruction at the
  // end.
  size_t instruction_boundary = kInvalidInstructionBoundary;

  // Indicates if the displacement information is valid for the instruction it
  // is assosiated. For example, an unconditional direct branch will have a
  // valid branch displacement, but an add operation will not.
  // `instruction_boundary` may be invalid for a brief period when decoding new
  // instructions, so check `encoded_byte_displacement` instead.
  bool valid() const {
    return encoded_byte_displacement != kInvalidByteDisplacement;
  }
};

// This could be 15, but round up to 16 to make it a nice power of 2.
constexpr const size_t kInsnBufferSize = 16;

// Instruction data is a container with inline storage.
// The intent is to reduce allocator thrash and make cloning a program faster.
class InstructionData {
 public:
  InstructionData() { Clear(); }

  InstructionData(const uint8_t* bytes, size_t num_bytes) {
    Copy(bytes, num_bytes);
  }

  // Copyable.
  InstructionData(const InstructionData& other) = default;
  InstructionData& operator=(const InstructionData& other) = default;

  // Moveable.
  InstructionData(InstructionData&& other) = default;
  InstructionData& operator=(InstructionData&& other) = default;

  void Clear() { num_bytes_ = 0; }

  // Copy the data contained in `bytes` into this data structure.
  void Copy(const uint8_t* bytes, size_t num_bytes);

  // Methods to access raw data.
  uint8_t* data() { return bytes_; }
  const uint8_t* data() const { return bytes_; }
  size_t size() const { return num_bytes_; }

  // Methods to iterate.
  const uint8_t* begin() const { return bytes_; }
  const uint8_t* end() const { return bytes_ + num_bytes_; }

 private:
  uint8_t bytes_[kInsnBufferSize];
  size_t num_bytes_;
};

struct Instruction {
  // The encoded bytes of the instruction.
  InstructionData encoded;

  // Info about the direct branch contained in this instruction, if it exists.
  InstructionDisplacementInfo direct_branch;

  // The byte offset of the instruction inside the program.
  // We allow this to get out of sync while the program is mutated, and then
  // recalculate it while we do the final branch fixup before outputting the
  // mutated program.
  uint64_t offset;
};

// A program is a linear sequence of instructions that may execute in a very
// non-linear way.
// This structure is designed to be copied.
class Program {
 public:
  Program();

  // Disassemble a sequence of bytes into a sequence of instructions. We assume
  // that a program consists of a sequence of non-overlapping instructions with
  // no gaps between them.
  // When we construct a program we try to accept arbitrary inputs to the
  // greatest extent we can. That means dropping instructions that either failed
  // to decode or did decode and were filtered out.
  // `strict` indicates we are certain these bytes correspond to a completely
  // valid program and should not require any fixup, and we should CHECK this is
  // the case.
  Program(const uint8_t* bytes, size_t len, bool strict = false);

  Program(const std::vector<uint8_t>& bytes, bool strict = false)
      : Program(bytes.data(), bytes.size(), strict) {}

  // Copyable.
  Program(const Program& other) = default;
  Program& operator=(const Program& other) = default;

  // Moveable.
  Program(Program&& other) = default;
  Program& operator=(Program&& other) = default;

  // Note that GetInstruction returns a const reference. This is so the state of
  // Program cannot be modified without going through a method that maintains
  // internal invariants like SetInstruction.
  const Instruction& GetInstruction(size_t index) const {
    return instructions_[index];
  }

  // Overwrite the instruction at `index` with `insn`.
  void SetInstruction(size_t index, const Instruction& insn);

  size_t NumInstructions() const { return instructions_.size(); }

  size_t NumInstructionBoundaries() const { return instructions_.size() + 1; }

  size_t RandomInstructionIndex(MutatorRng& rng) {
    return RandomIndex(rng, NumInstructions());
  }

  size_t RandomInstructionBoundary(MutatorRng& rng) {
    return RandomIndex(rng, NumInstructionBoundaries());
  }

  // Insert an instruction at a specific instruction boundary in the program.
  // A `boundary` is either before an instruction, or at the end of the program.
  // `steal_displacements` indicates which side of the boundary the instruction
  // is being inserted on.
  // If `steal_displacements` is true, the instruction is inserted after the
  // boundary and any branches to the boundary are now branches to the
  // instruction.
  // If `steal_displacements` is false, the instruction is inserted before the
  // boundary and branches to the boundary remain pointed at the instruction
  // originally at the boundary.
  // Stealing displacements allows new instructions to be inserted inside a
  // single-instruction loop.  Not stealing displacements allows
  // single-instruction loops to remain undisturbed. A mutator will want to
  // randomize the kind of insert it performs.
  void InsertInstruction(size_t boundary, bool steal_displacements,
                         const Instruction& insn);

  // Remove a specific instruction.
  void RemoveInstruction(size_t index);

  // Assert the internal data structure invariants are correct.
  // Exposed for testing.
  void CheckConsistency() const;

  // Length of the program, in bytes.
  size_t ByteLen() const { return byte_len_; }

  // The encoded displacement in an instruction may not point to the instruction
  // we want it to point to. Reassemble these instructions with the desired
  // displacement. In some cases it may be impossible to encode the desired
  // displacement in an instruction of the given type. In this case we randomize
  // the instruction the displacement points to until it can be encoded.
  // Returns `true` if the program was modified.
  bool FixupEncodedDisplacements(MutatorRng& rng);

  // Convert the program to a linear sequence of bytes.
  // Assumes either the program is unmodified or that FixupEncodedDisplacements
  // has been called first.
  void ToBytes(std::vector<uint8_t>& output) const;

 private:
  // Recalculate the offset of each instruction and the program size.
  void FixupInvariants();

  // Shift instruction indexes >= `boundary` by `amount`.
  // Whenever an instruction is inserted or removed from a program, we need to
  // shift any instruction indexes that point after the insertion or removal
  // point.
  void AdjustInstructionIndexes(size_t boundary, int64_t amount);

  // Resolve instruction displacements into instruction boundaries.
  // This is called after the program is initially decompiled. Afterwards the
  // instruction boundary is considered the source of truth and the displacement
  // will be modified so that it stays pointing at the bondary.
  // If `strict` is true, this function requires that displacements point
  // exactly at instruction boundaries. Otherwise it chooses the nearest
  // boundary.
  void ResolveDisplacements(bool strict);

  size_t FindClosestInstructionBoundary(int64_t program_offset);

  int64_t InstructionBoundaryToProgramByteOffset(size_t boundary) const;

  // Update the byte displacements to match the instruction indexes. Return true
  // if the byte displacements changed.
  // Generally the byte displacements should match the encoded instruction, so
  // is syncing changes the values the instruction should be immediately
  // re-encoded.
  bool SyncByteDisplacements(Instruction& insn);
  bool SyncByteDisplacement(const Instruction& insn,
                            InstructionDisplacementInfo& info);

  // The instructions in the program.
  // They are assumed to be packed end-to-end and do not overlap.
  std::vector<Instruction> instructions_;

  // The total size of the program.
  uint64_t byte_len_;

  // The program has been edited and requires fixup.
  // Used to check that the API is being used correctly.
  bool encodings_may_be_invalid;
};

// These functions are exported because they are useful both for a mutator and
// for fixing up the displacements in a program.

// Randomize the PC-relative displacements of this instruction so that they
// point to a random, valid instruction boundary within the program.
// Does not re-encode the instruction, only randomizes what the displacements
// _should_ be. The encoding will be fixed up later, if needed.
void RandomizeInstructionDisplacementBoundaries(MutatorRng& rng,
                                                Instruction& insn,
                                                size_t num_boundaries);

// Similar to above, but for a single displacement.
void RandomizeInstructionDisplacementBoundary(MutatorRng& rng,
                                              InstructionDisplacementInfo& info,
                                              size_t num_boundaries);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_PROGRAM_H_
