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

#ifndef THIRD_PARTY_SILIFUZZ_INSTRUCTION_XED_UTIL_H_
#define THIRD_PARTY_SILIFUZZ_INSTRUCTION_XED_UTIL_H_

#include <cstddef>
#include <cstdint>
#include <utility>

#include "./util/platform.h"

extern "C" {
#include "third_party/libxed/xed-interface.h"
}

namespace silifuzz {

// Lazy init XED. Must be called before XED is used.
void InitXedIfNeeded();

// Convert the instruction to a human-readable string.
// `address` is the location of the instruction in memory. This can affect the
// output. For example, relative displacements are formatted as absolute
// addresses.
// This functionality is wrapped in a function to reduce boilerplate and make
// sure one corner case is done right.
bool FormatInstruction(const xed_decoded_inst_t& instruction, uint64_t address,
                       char* buffer, size_t buffer_size);

// Checks if an instruction is allowed to run in the runner.
// For example, non-deterministic and privileged instructions are not allowed.
bool InstructionIsAllowedInRunner(const xed_inst_t* instruction);

// Does this instruction produce the same result every time when it is run
// inside the runner? An obvious type of instruction that is non-deterministic
// are instructions that produce random numbers. A less obvious type of
// instruction are instructions that depend on state the runner does not /
// cannot control.
bool InstructionClassIsAllowedInRunner(const xed_inst_t* instruction);

// Is this an unprivileged instruction? Useful for filtering instructions before
// the run on hardware. Once they run on hardware, the answer should be obvious.
bool InstructionCanRunInUserSpace(const xed_inst_t* instruction);

// Is this an IO instruction? IO instructions can run in user space, but the
// runner does not have the privilege to do so.
bool InstructionRequiresIOPrivileges(const xed_inst_t* instruction);

// Can this instruction alter the instruction pointer?
bool InstructionIsBranch(const xed_inst_t* instruction);

// Is this an X87 instruction?
// X87 instructions can push/pop the register file. Some instructions can have
// high latencies.
bool InstructionIsX87(const xed_inst_t* instruction);

// Is this an SSE instruction?
// Some chips may have a penalty for mixing SSE and AVX instructions.
bool InstructionIsSSE(const xed_inst_t* instruction);

// Is this an AVX512 EVEX instruction?
bool InstructionIsAVX512EVEX(const xed_inst_t* instruction);

// Translate a Silifuzz platform ID to a XED chip enum.
xed_chip_enum_t PlatformIdToChip(PlatformId platform_id);

// Return the size of the widest addressable vector registers on this chip, in
// bits. Returns 0 if the chip does not have vector registers.
unsigned int ChipVectorRegisterWidth(xed_chip_enum_t chip);

// Return the size of the widest addressable mask registers on this chip, in
// bits. Returns 0 if the chip does not have mask registers.
unsigned int ChipMaskRegisterWidth(xed_chip_enum_t chip);

// A wrapper for the XED instruction encoding interface that allows incremental
// specification of each operand. The native XED interface requires all operands
// to be specified at once.
class InstructionBuilder {
 public:
  InstructionBuilder(xed_iclass_enum_t iclass, unsigned int effective_op_width)
      : iclass_(iclass), effective_op_width_(effective_op_width) {}

  template <typename... Args>
  void AddOperands(xed_encoder_operand_t&& operand, Args&&... args) {
    operands_[num_operands_++] = std::move(operand);
    AddOperands(std::forward<Args>(args)...);
  }

  [[nodiscard]] bool Encode(uint8_t* buf, size_t& len);

  xed_iclass_enum_t iclass() const { return iclass_; }

 private:
  // Base case to terminate vardic recursion.
  void AddOperands() {}

  xed_iclass_enum_t iclass_;
  unsigned int effective_op_width_;

  xed_uint_t num_operands_ = 0;
  xed_encoder_operand_t operands_[XED_ENCODER_OPERANDS_MAX];
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_INSTRUCTION_XED_UTIL_H_
