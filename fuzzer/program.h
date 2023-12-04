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
#include <vector>

namespace silifuzz {

constexpr size_t kInvalidInstructionBoundary =
    std::numeric_limits<size_t>::max();

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

  const Instruction& GetInstruction(size_t index) const {
    return instructions_[index];
  }

  size_t NumInstructions() const { return instructions_.size(); }

  size_t NumInstructionBoundaries() const { return instructions_.size() + 1; }

  // Insert an instruction at a specific instruction boundary in the program.
  // A `boundary` is either before an instruction, or at the end of the program.
  void InsertInstruction(size_t boundary, const Instruction& insn);

  // Remove a specific instruction.
  void RemoveInstruction(size_t index);

  // Assert the internal data structure invariants are correct.
  // Exposed for testing.
  void CheckConsistency() const;

  // Length of the program, in bytes.
  size_t ByteLen() const { return byte_len_; }

  // Convert the program to a linear sequence of bytes.
  void ToBytes(std::vector<uint8_t>& output);

 private:
  // Recalculate the offset of each instruction and the program size.
  void FixupInvariants();

  // The instructions in the program.
  // They are assumed to be packed end-to-end and do not overlap.
  std::vector<Instruction> instructions_;

  // The total size of the program.
  uint64_t byte_len_;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_PROGRAM_H_
