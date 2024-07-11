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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_SYNTHESIZE_INSTRUCTION_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_SYNTHESIZE_INSTRUCTION_H_

#include <cstddef>
#include <cstdint>
#include <random>
#include <vector>

#include "./fuzzer/hashtest/candidate.h"
#include "./fuzzer/hashtest/register_info.h"

namespace silifuzz {

// RNG used for random instruction and test generation.
using Rng = std::mt19937_64;

// The layout of registers for generating instructions and tests.
// `tmp` registers can be used for any purpose. If a register is "fixed" for any
// instruction (for example the SSE4.1 version of BLENDVPS will always read from
// XMM0) that register must be contained in `tmp`.
// `entropy` registers contain high-entropy values. These registers contain
// state that is updated and persists throughout the test. They are mutually
// exclusive with `tmp` registers.
// `vec_width` is the maximum vector register width that should be used.
// `mask_width` is the maximum mask register width that should be used.
struct RegisterPool {
  RegisterMask tmp;
  RegisterMask entropy;
  size_t vec_width;
  size_t mask_width;
};

// Synthesize a randomized instruction based on `candidate`.
// Used temp and entropy registers will be removed from `rpool`.
[[nodiscard]] bool SynthesizeTestInstruction(
    const InstructionCandidate& candidate, RegisterPool& rpool, Rng& rng,
    unsigned int effective_op_width, std::vector<RegisterID>& needs_init,
    std::vector<unsigned int>& is_written, uint8_t* ibuf, size_t& ibuf_len);

// Helpers for generating XED register operands.
xed_encoder_operand_t GPRegOperand(unsigned int index, size_t width);
xed_encoder_operand_t VecRegOperand(unsigned int index, size_t width);
xed_encoder_operand_t MaskRegOperand(unsigned int index);
xed_encoder_operand_t MMXRegOperand(unsigned int index);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_SYNTHESIZE_INSTRUCTION_H_
