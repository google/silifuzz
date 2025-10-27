// Copyright 2024 The Silifuzz Authors.
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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_TESTGENERATION_CANDIDATE_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_TESTGENERATION_CANDIDATE_H_

#include <cstddef>

#include "./fuzzer/hashtest/testgeneration/register_info.h"

extern "C" {
#include "third_party/libxed/xed-interface.h"
}

namespace silifuzz {

// A read/write bitmask of the registers.
struct RegisterReadWrite {
  RegisterMask read;
  RegisterMask written;
};

// Information about an instruction we may be able to incorporate into a
// randomized test.
struct InstructionCandidate {
  const xed_inst_t* instruction = nullptr;

  // The number of each type of register read and written by this instruction.
  // Used to help classify what kind of instruction this is.
  RegisterCount reg_read;
  RegisterCount reg_written;

  // A bitmask of the fixed registers read and written by this instruction.
  RegisterReadWrite fixed_reg;

  // The width of the vector instruction - 128/256/512 bits, or zero if not a
  // vector instruction.
  size_t vector_width = 0;

  // Does the instruction support an effective width of 16/32/64 bits?
  bool width_16 = false;
  bool width_32 = false;
  bool width_64 = false;

  // Does the instruction support a write mask?
  // When a writemask is used, the destination register may not be completely
  // overwritten and needs to be treated as in/out similar to a conditional
  // move.
  bool writemask = false;

  // What register bank does this instruction write to?
  RegisterBank OutputMode() const;
};

// Returns true if the instruction is a candidate for inclusion in a test.
// If the instruction is a candidate, the `candidate` parameter is filled in.
bool IsCandidate(const xed_inst_t* instruction,
                 InstructionCandidate& candidate);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_TESTGENERATION_CANDIDATE_H_
