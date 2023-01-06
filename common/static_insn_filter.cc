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
// Start here: C4.1 A64 instruction set encoding

struct InstructionBits {
  uint32_t mask;
  uint32_t bits;

  constexpr bool matches(uint32_t insn) const { return (insn & mask) == bits; }
};

struct RequiredInstructionBits {
  InstructionBits pattern;
  InstructionBits expect;
  constexpr bool violates_requirements(uint32_t insn) const {
    return pattern.matches(insn) && !expect.matches(insn);
  }
};

constexpr InstructionBits kBannedInstructions[] = {
    // See: C4.1.66 Loads and Stores
    // Should cover STLXR, STLXRB, STLXRH, and STLXP but not LDAXR, STR, etc.
    // Bit 22 => 0, this is a store.
    // Bit 21 => X, cover both store register and store pair.
    // Store exclusive can succeed or fail in a non-deterministic manner.
    // Its exact behavior can depend on a variety of factors, such as another
    // snapshot doing a load exclusive or store exclusive to the same address.
    // It may also depend on if the address is in the cache or not or if context
    // is swapped out between executing the load and the store.
    {
        .mask = 0b0011'1111'1100'0000'0000'0000'0000'0000,
        .bits = 0b0000'1000'0000'0000'0000'0000'0000'0000,
    },
};

constexpr RequiredInstructionBits kRequiredInstructionBits[] = {
    {
        // See: C4.1.65 Branches, Exception Generating and System
        // instructions
        .pattern =
            {
                .mask = 0b1111'1111'0000'0000'0000'0000'0000'0000,
                .bits = 0b1101'0101'0000'0000'0000'0000'0000'0000,
            },
        // The spec currently does not define any system instructions that have
        // non-zero bits for 22 and 23. Some versions of QEMU do not check this.
        .expect =
            {
                .mask = 0b0000'0000'1100'0000'0000'0000'0000'0000,
                .bits = 0b0000'0000'0000'0000'0000'0000'0000'0000,
            },
    },
    {
        // See: C4.1.66 Loads and Stores
        // Should cover all compare and swap instructions.
        .pattern =
            {
                .mask = 0b0011'1111'1010'0000'0000'0000'0000'0000,
                .bits = 0b0000'1000'1010'0000'0000'0000'0000'0000,
            },
        // The spec declares Rt2 != 11111 (xzr) "unallocated". Some versions of
        // QEMU do not check this.
        .expect =
            {
                .mask = 0b0000'0000'0000'0000'0111'1100'0000'0000,
                .bits = 0b0000'0000'0000'0000'0111'1100'0000'0000,
            },
    },
    {
        // C4.1.68 Data Processing -- Register
        // Add/subtract (extended register)
        .pattern =
            {
                .mask = 0b0001'1111'0010'0000'0000'0000'0000'0000,
                .bits = 0b0000'1011'0010'0000'0000'0000'0000'0000,
            },
        // The spec declares Opt (bits 23:22) != 00 "unallocated". Some versions
        // of QEMU do not check this.
        .expect =
            {
                .mask = 0b0000'0000'1100'0000'0000'0000'0000'0000,
                .bits = 0b0000'0000'0000'0000'0000'0000'0000'0000,
            },
    },
    {
        // C4.1.68 Data Processing -- Register
        // Floating-point data-processing (3 source)
        .pattern =
            {
                .mask = 0b0101'1111'0000'0000'0000'0000'0000'0000,
                .bits = 0b0001'1111'0000'0000'0000'0000'0000'0000,
            },
        // The spec declares M (bit 31) != 0 is "unallocated".
        // The spec declares S (bit 29) != 0 is "unallocated".
        .expect =
            {
                .mask = 0b1010'0000'0000'0000'0000'0000'0000'0000,
                .bits = 0b0000'0000'0000'0000'0000'0000'0000'0000,
            },
    },
};

constexpr bool InstructionIsOK(uint32_t insn) {
  for (const InstructionBits& bits : kBannedInstructions) {
    if (bits.matches(insn)) {
      return false;
    }
  }
  for (const RequiredInstructionBits& bits : kRequiredInstructionBits) {
    if (bits.violates_requirements(insn)) {
      return false;
    }
  }
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
