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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_TESTGENERATION_DEBUGGING_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_TESTGENERATION_DEBUGGING_H_

#include "absl/base/attributes.h"

extern "C" {
#include "third_party/libxed/xed-interface.h"
}

namespace silifuzz {

// Print human-readable information about the instruction.
// Helps visualize the information that XED associates with each instruction.
void DumpInstruction(const xed_inst_t* instruction);

// Print information about the instruction and operand, then kill the process.
// Intended to mark places where we do not support a certain type of operand.
ABSL_ATTRIBUTE_NORETURN void DieBecauseOperand(const xed_inst_t* instruction,
                                               const xed_operand_t* operand);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_TESTGENERATION_DEBUGGING_H_
