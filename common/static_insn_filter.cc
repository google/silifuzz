// Copyright 2022 The SiliFuzz Authors.
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

#include "./common/static_insn_filter.h"

#include <cstdint>

#include "./util/arch.h"

namespace silifuzz {

template <>
bool StaticInstructionFilter<X86_64>(absl::string_view code) {
  // It's difficult to reliably disassemble x86_64 instructions, so for now we
  // don't try.
  return true;
}

// aarch64 filter
namespace {
// See the ARM ARM (Architechture Reference Manual) for the details of
// instruction encoding:  https://developer.arm.com/documentation/ddi0487/latest

// See: C4.1.66 Loads and Stores
// Should cover STLXR, STLXRB, STLXRH, and STLXP but not LDAXR, STR, etc.
// Bit 22 => 0, this is a store.
// Bit 21 => X, cover both store register and store pair.
constexpr uint32_t kStoreExclusiveMask =
    0b0011'1111'1100'0000'0000'0000'0000'0000;
constexpr uint32_t kStoreExclusiveBits =
    0b0000'1000'0000'0000'0000'0000'0000'0000;

// Store exclusive can succeed or fail in a non-deterministic manner.
// Its exact behavior can depend on a variety of factors, such as another
// snapshot doing a load exclusive or store exclusive to the same address.
// It may also depend on if the address is in the cache or not.
constexpr bool IsStoreExclusive(uint32_t insn) {
  return (insn & kStoreExclusiveMask) == kStoreExclusiveBits;
}

bool InstructionIsOK(uint32_t insn) {
  if (IsStoreExclusive(insn)) return false;
  return true;
}

}  // namespace

// For aarch64 we filter out any instruction sequence that contains a
// questionable instruction, even though we don't know for certain those bytes
// will be executed. A later mutation could make the instruction live.
template <>
bool StaticInstructionFilter<AArch64>(absl::string_view code) {
  if (code.size() % 4 != 0) return false;

  const uint32_t* begin = reinterpret_cast<const uint32_t*>(code.data());
  const uint32_t* end = begin + code.size() / sizeof(uint32_t);

  for (const uint32_t* insn = begin; insn < end; ++insn) {
    if (!InstructionIsOK(*insn)) return false;
  }

  return true;
}

}  // namespace silifuzz
