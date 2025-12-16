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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_TESTGENERATION_SYNTHESIZE_BASE_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_TESTGENERATION_SYNTHESIZE_BASE_H_

#include <cstddef>
#include <cstdint>
#include <vector>

#include "absl/base/attributes.h"
#include "absl/strings/string_view.h"
#include "./fuzzer/hashtest/testgeneration/register_info.h"
#include "./instruction/xed_util.h"

extern "C" {
#include "third_party/libxed/xed-interface.h"
}

namespace silifuzz {

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

// The GP register that holds the loop count.
inline constexpr unsigned int kLoopIndex = 8;

// Mark which registers are usable as temporary values and which registers are
// part of the entropy pool.
void InitRegisterLayout(xed_chip_enum_t chip, RegisterPool& rpool);

// A buffer for collecting emitted instructions.
struct InstructionBlock {
  void EmitInstruction(const uint8_t* ptr, size_t len) {
    bytes.insert(bytes.end(), ptr, ptr + len);
    num_instructions++;
  }

  void Append(const InstructionBlock& other) {
    bytes.insert(bytes.end(), other.bytes.begin(), other.bytes.end());
    num_instructions += other.num_instructions;
  }

  absl::string_view View() const ABSL_ATTRIBUTE_LIFETIME_BOUND {
    return absl::string_view(reinterpret_cast<const char*>(bytes.data()),
                             bytes.size());
  }

  std::vector<uint8_t> bytes;
  size_t num_instructions = 0;
};

// Encode the instruction and append it to the instruction block.
void Emit(InstructionBuilder& builder, InstructionBlock& block);

// Helpers for generating XED register operands.
xed_encoder_operand_t GPRegOperand(unsigned int index, size_t width);
xed_encoder_operand_t VecRegOperand(unsigned int index, size_t width);
xed_encoder_operand_t MaskRegOperand(unsigned int index);
xed_encoder_operand_t MMXRegOperand(unsigned int index);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_TESTGENERATION_SYNTHESIZE_BASE_H_
