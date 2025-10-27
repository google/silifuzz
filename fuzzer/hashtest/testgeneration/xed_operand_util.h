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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_TESTGENERATION_XED_OPERAND_UTIL_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_TESTGENERATION_XED_OPERAND_UTIL_H_

#include <cstddef>

extern "C" {
#include "third_party/libxed/xed-interface.h"
}

namespace silifuzz {

// Predicates for operand visibility.

// An explicit operand must be specified when encoding the instruction, and can
// more-or-less be set to arbitrary values.
bool OperandIsExplicit(const xed_operand_t* operand);

// An implicit operand must also be specified when encoding the instruction, but
// must take on specific values. This is typically because an IFORM is a
// specialized encoding of the ICLASS, for example an ADD instruction that can
// add 1 to an A register.
bool OperandIsImplicit(const xed_operand_t* operand);

// A suppressed operand is not specified when encoding the instruction, but
// indicates that the instruction has some sort of side effect - for example
// reading or writing the flags register.
bool OperandIsSuppressed(const xed_operand_t* operand);

// Predicates for operand types.

bool OperandIsFlagRegister(const xed_operand_t* operand);

bool OperandIsSegmentRegister(const xed_operand_t* operand);

bool OperandIsMMXRegister(const xed_operand_t* operand);

bool OperandIsXMMRegister(const xed_operand_t* operand);

bool OperandIsYMMRegister(const xed_operand_t* operand);

bool OperandIsZMMRegister(const xed_operand_t* operand);

bool OperandIsVectorRegister(const xed_operand_t* operand);

bool OperandIsMaskRegister(const xed_operand_t* operand);

bool OperandIsWritemask(const xed_operand_t* operand);

bool OperandIsGPRegister(const xed_operand_t* operand);

bool OperandIsAddressGPRegister(const xed_operand_t* operand);

bool OperandIsTile(const xed_operand_t* operand);

bool OperandIsRegister(const xed_operand_t* operand);

bool OperandIsImmediate(const xed_operand_t* operand);

bool OperandIsMemory(const xed_operand_t* operand);

// Determining the bit width of specific types of operands.

// Returns the bit width of the operand, given the effective operand width.
// This function is only valid for operands that can be affected by the
// effective operand width - general purpose registers, immediate operands, etc.
// Vector register operands are not valid.
size_t OperandBitWidth(const xed_operand_t* operand,
                       unsigned int effective_op_width);

// Return the bit width of a vector register operand.
size_t VectorWidth(const xed_operand_t* operand);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_TESTGENERATION_XED_OPERAND_UTIL_H_
