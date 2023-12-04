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

#include <cstdint>
#include <cstring>
#include <vector>

#include "absl/log/check.h"
#include "./fuzzer/program_arch.h"

namespace silifuzz {

void InstructionData::Copy(const uint8_t* bytes, size_t num_bytes) {
  CHECK_LE(num_bytes, sizeof(bytes_));
  memcpy(bytes_, bytes, num_bytes);
  num_bytes_ = num_bytes;
}

void Program::CheckConsistency() const {
  size_t actual_len = 0;
  for (const Instruction& insn : instructions_) {
    actual_len += insn.encoded.size();
  }
  CHECK_EQ(byte_len_, actual_len);
}

void Program::FixupInvariants() {
  uint64_t offset = 0;
  for (Instruction& insn : instructions_) {
    insn.offset = offset;
    offset += insn.encoded.size();
  }
  byte_len_ = offset;
}

Program::Program() : byte_len_(0) { ArchSpecificInit(); }

Program::Program(const uint8_t* bytes, size_t len, bool strict) {
  ArchSpecificInit();

  size_t offset = 0;
  while (offset < len) {
    Instruction instruction;
    if (InstructionFromBytes(&bytes[offset], len - offset, instruction)) {
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
        // consume. Consume one byte - hopefully the decoding will reconverge
        // at some point.
        insn_len = 1;
      }
      offset += insn_len;
    }
  }

  // Lay out the instructions one after each other.
  FixupInvariants();
}

void Program::InsertInstruction(size_t boundary, const Instruction& insn) {
  CHECK_LT(boundary, NumInstructionBoundaries());

  // Insert the instruction.
  byte_len_ += insn.encoded.size();
  instructions_.insert(instructions_.begin() + boundary, insn);

  // TODO(ncbray): Do we really need to stay in sync?
  FixupInvariants();
}

void Program::RemoveInstruction(size_t index) {
  CHECK_LT(index, NumInstructions());

  // Remove the instruction.
  byte_len_ -= instructions_[index].encoded.size();
  instructions_.erase(instructions_.begin() + index);

  // TODO(ncbray): Do we really need to stay in sync?
  FixupInvariants();
}

void Program::ToBytes(std::vector<uint8_t>& output) {
  output.clear();
  output.reserve(byte_len_);
  for (const Instruction& insn : instructions_) {
    CHECK_EQ(insn.offset, output.size());
    output.insert(output.end(), insn.encoded.begin(), insn.encoded.end());
  }
}

}  // namespace silifuzz
