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

#ifndef THIRD_PARTY_SILIFUZZ_TRACING_XED_DISASSEMBLER_H_
#define THIRD_PARTY_SILIFUZZ_TRACING_XED_DISASSEMBLER_H_

#include <cstddef>
#include <cstdint>
#include <string>

#include "./tracing/disassembler.h"
#include "./util/arch.h"

extern "C" {
#include "third_party/libxed/xed-interface.h"
}

namespace silifuzz {

// This class wraps XED for use by instruction tracers.
// This class is not thread safe since a XED instance is not thread safe.
class XedDisassembler : public Disassembler {
 public:
  XedDisassembler();
  ~XedDisassembler();

  // Non-copyable / non-moveable.
  XedDisassembler(const XedDisassembler&) = delete;
  XedDisassembler(XedDisassembler&&) = delete;
  XedDisassembler& operator=(const XedDisassembler&) = delete;
  XedDisassembler& operator=(XedDisassembler&&) = delete;

  // Disassmeble a single instruction.
  // `address` is the address of the instruction being disassembled. The address
  // is required to print absolute jump targets.
  // `buffer` points to memory that contains the complete instruction. It is OK
  // if it contains additional data.
  // `buffer_size` specifies the amount of data available in `buffer`. Only part
  // of that data may be consumed.
  // Returns the true if the instruction is valid.
  bool Disassemble(uint64_t address, const uint8_t* buffer,
                   size_t buffer_size) override;

  // How much data was consumed by the last call to Disassemble.
  [[nodiscard]] size_t InstructionSize() const override;

  [[nodiscard]] virtual bool CanBranch() const override;

  // The textual representation of the last instruction that was disassembled.
  [[nodiscard]] std::string FullText() override;

  // A numerical ID for the last type of instruction that was disassembled.
  [[nodiscard]] uint32_t InstructionID() const override;

  [[nodiscard]] uint32_t InvalidInstructionID() const override;

  // The number of possible instruction IDs.
  [[nodiscard]] uint32_t NumInstructionIDs() const override;

  // A human-readable name for the instruction ID.
  [[nodiscard]] std::string InstructionIDName(uint32_t id) const override;

 private:
  xed_decoded_inst_t xedd_;
  uint64_t address_;
  char full_text_[96];
  bool valid_;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_TRACING_XED_DISASSEMBLER_H_
