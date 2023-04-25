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

#ifndef THIRD_PARTY_SILIFUZZ_TRACING_CAPSTONE_DISASSEMBLER_H_
#define THIRD_PARTY_SILIFUZZ_TRACING_CAPSTONE_DISASSEMBLER_H_

#include <stddef.h>
#include <stdint.h>

#include <string>

#include "third_party/capstone/capstone.h"
#include "./util/arch.h"

namespace silifuzz {

// This class wraps Capstone for use by instruction tracers.
// The goal is to provide a disassembler-neutral interface so that other
// disassemblers can be swaped in as desired.
// This class is not thread safe since a capstone instance is not thread safe.
class CapstoneDisassembler {
 public:
  CapstoneDisassembler(ArchitectureId arch_id);
  ~CapstoneDisassembler();

  // Non-copyable / non-moveable.
  CapstoneDisassembler(const CapstoneDisassembler&) = delete;
  CapstoneDisassembler(CapstoneDisassembler&&) = delete;
  CapstoneDisassembler& operator=(const CapstoneDisassembler&) = delete;
  CapstoneDisassembler& operator=(CapstoneDisassembler&&) = delete;

  // Disassmeble a single instruction.
  // `address` is the address of the instruction being disassembled. The address
  // is required to print absolute jump targets.
  // `buffer` points to memory that contains the complete instruction. It is OK
  // if it contains additional data.
  // `buffer_size` is an in/out that specifies the total amount data passed in,
  // as well as the amount of data consumed.
  // Returns the true if the instruction is valid.
  [[nodiscard]] bool Disassemble(uint64_t address, const uint8_t* buffer,
                                 size_t* buffer_size);

  // How much data was consumed by the last call to Disassemble.
  [[nodiscard]] size_t InstructionSize() const;

  // The textual representation of the last instruction that was disassembled.
  [[nodiscard]] std::string FullText() const;

 private:
  csh capstone_handle_;
  cs_insn* decoded_insn_;
  bool valid_;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_TRACING_CAPSTONE_DISASSEMBLER_H_
