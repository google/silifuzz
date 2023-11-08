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

// Does this instruction produce the same result every time when it is run
// inside the runner? An obvious type of instruction that is non-deterministic
// are instructions that produce random numbers. A less obvious type of
// instruction are instructions that depend on state the runner does not /
// cannot control.
bool InstructionIsDeterministicInRunner(const xed_decoded_inst_t& instruction);

// Is this an unprivileged instruction? Useful for filtering instructions before
// the run on hardware. Once they run on hardware, the answer should be obvious.
bool InstructionCanRunInUserSpace(const xed_decoded_inst_t& instruction);

// Is this an IO instruction? IO instructions can run in user space, but the
// runner does not have the privilege to do so.
bool InstructionRequiresIOPrivileges(const xed_decoded_inst_t& instruction);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_INSTRUCTION_XED_UTIL_H_
