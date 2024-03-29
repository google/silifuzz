// Copyright 2023 The SiliFuzz Authors.
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

#ifndef THIRD_PARTY_SILIFUZZ_INSTRUCTION_DISASSEMBLER_H_
#define THIRD_PARTY_SILIFUZZ_INSTRUCTION_DISASSEMBLER_H_

#include <cstddef>
#include <cstdint>
#include <string>

namespace silifuzz {

inline constexpr const char* kInvalidInstructionName = "unknown";

// Generic disassembler interface.
// The underlying implementation will likely not be thread safe, users of this
// inferface should assume it is not thread safe.
class Disassembler {
 public:
  Disassembler() = default;
  virtual ~Disassembler() = default;

  // Non-copyable / non-moveable.
  Disassembler(const Disassembler&) = delete;
  Disassembler(Disassembler&&) = delete;
  Disassembler& operator=(const Disassembler&) = delete;
  Disassembler& operator=(Disassembler&&) = delete;

  // Disassemble a single instruction.
  // `address` is the address of the instruction being disassembled. The address
  // is required to print absolute jump targets.
  // `buffer` points to memory that contains the complete instruction. It is OK
  // if it contains additional data.
  // `buffer_size` specifies the amount of data available in `buffer`. Only part
  // of that data may be consumed.
  // Returns the true if the instruction is valid.
  virtual bool Disassemble(uint64_t address, const uint8_t* buffer,
                           size_t buffer_size) = 0;

  // How much data was consumed by the last call to Disassemble.
  [[nodiscard]] virtual size_t InstructionSize() const = 0;

  // Can this instruction modify the instruction pointer, in some way?
  // Includes direct jumps, indirect jumps, calls, returns, etc.
  [[nodiscard]] virtual bool CanBranch() const = 0;

  // Can this instruction read from memory, in some way?
  [[nodiscard]] virtual bool CanLoad() const = 0;

  // Can this instruction write to memory, in some way?
  [[nodiscard]] virtual bool CanStore() const = 0;

  // The textual representation of the last instruction that was disassembled.
  [[nodiscard]] virtual std::string FullText() = 0;

  // A numerical ID for the last type of instruction that was disassembled.
  [[nodiscard]] virtual uint32_t InstructionID() const = 0;

  // The value that InstructionID() returns after Disassmble() fails.
  // It is required that InvalidInstructionID() < NumInstructionIDs()
  [[nodiscard]] virtual uint32_t InvalidInstructionID() const = 0;

  // The number of possible instruction IDs.
  [[nodiscard]] virtual uint32_t NumInstructionIDs() const = 0;

  // A human-readable name for the instruction ID.
  [[nodiscard]] virtual std::string InstructionIDName(uint32_t id) const = 0;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_INSTRUCTION_DISASSEMBLER_H_
