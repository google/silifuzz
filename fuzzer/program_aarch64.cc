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

#include <cstddef>
#include <cstdint>

#include "absl/log/check.h"
#include "absl/strings/string_view.h"
#include "./fuzzer/program.h"
#include "./fuzzer/program_arch.h"  // IWYU pragma: keep
#include "./instruction/capstone_disassembler.h"
#include "./instruction/static_insn_filter.h"
#include "./util/arch.h"
#include "./util/bit_matcher.h"

namespace silifuzz {

namespace {

struct FieldLocation {
  uint8_t lsb;
  uint8_t width;
};

struct BranchInstructionInfo {
  BitMatcher<uint32_t> matcher;
  FieldLocation displacement;
};

constexpr BranchInstructionInfo kBranchInstructionInfo[] = {
    {
        // b and bl - unconditional direct branches
        .matcher =
            {
                .mask = 0b0111'1100'0000'0000'0000'0000'0000'0000,
                .bits = 0b0001'0100'0000'0000'0000'0000'0000'0000,
            },
        .displacement =
            {
                .lsb = 0,
                .width = 26,
            },
    },
    {
        // b.cond and bc.cond - conditional direct branches
        .matcher =
            {
                .mask = 0b1111'1111'0000'0000'0000'0000'0000'0000,
                .bits = 0b0101'0100'0000'0000'0000'0000'0000'0000,
            },
        .displacement =
            {
                .lsb = 5,
                .width = 19,
            },
    },
    {
        // cbz and cbnz - compare and branch
        .matcher =
            {
                .mask = 0b0111'1110'0000'0000'0000'0000'0000'0000,
                .bits = 0b0011'0100'0000'0000'0000'0000'0000'0000,
            },
        .displacement =
            {
                .lsb = 5,
                .width = 19,
            },
    },
    {
        // tbz and tbnz - test and branch
        .matcher =
            {
                .mask = 0b0111'1110'0000'0000'0000'0000'0000'0000,
                .bits = 0b0011'0110'0000'0000'0000'0000'0000'0000,
            },
        .displacement =
            {
                .lsb = 5,
                .width = 14,
            },
    },
};

constexpr int32_t ExtractBranchDisplacement(uint32_t insn, uint8_t lsb,
                                            uint8_t width) {
  DCHECK_LE(width, 30);        // Otherwise the displacement would be > 32 bits.
  DCHECK_LE(lsb + width, 32);  // Otherwise field would not fit in insn.
  // AArch64 branch displacements fields must be sign extended and scaled by 4.
  // We sign extend by shifting the msb all the way to the left and then
  // shifting the field back into place.
  const uint8_t shift = 32 - width;
  return ((((int32_t)insn) >> lsb) << shift) >> (shift - 2);
}

constexpr uint32_t RewriteBranchDisplacement(uint32_t insn, uint8_t lsb,
                                             uint8_t width,
                                             int32_t displacement) {
  DCHECK_LE(width, 30);        // Otherwise the displacement would be > 32 bits.
  DCHECK_LE(lsb + width, 32);  // Otherwise field would not fit in insn.
  const uint32_t displacement_mask = ((1U << width) - 1) << lsb;
  return (insn & ~displacement_mask) |
         (((displacement >> 2) << lsb) & displacement_mask);
}

static_assert(RewriteBranchDisplacement(0x5400002f, 5, 19, -4) == 0x54ffffef,
              "Rewrite does not work as expected.");
static_assert(RewriteBranchDisplacement(0x54ffffef, 5, 19, 4) == 0x5400002f,
              "Rewrite does not work as expected.");

InstructionDisplacementInfo GetDirectBranchInfo(uint32_t insn) {
  for (const BranchInstructionInfo& info : kBranchInstructionInfo) {
    if (info.matcher.matches(insn)) {
      return {.encoded_byte_displacement = ExtractBranchDisplacement(
                  insn, info.displacement.lsb, info.displacement.width)};
    }
  }
  return {};
}

}  // namespace

template <>
void ArchSpecificInit<AArch64>() {}

template <>
bool InstructionFromBytes(const uint8_t* bytes, size_t num_bytes,
                          Instruction<AArch64>& instruction,
                          bool must_decode_everything) {
  // On decode failure, we want the length to be zero.
  instruction.encoded.Clear();

  if (num_bytes < 4) {
    return false;
  }

  // The instruction data.
  // If the instruction decodes, we want the length to be correct even if a
  // later filter rejects it. This lets higher-level code skip the bytes.
  instruction.encoded.Copy(bytes, 4);

  // TODO(ncbray): create at a higher level and pass down to avoid thrashing
  // the memory allocator.
  CapstoneDisassembler<AArch64> disassembler;
  if (!disassembler.Disassemble(0x0, bytes, num_bytes)) return false;

  uint32_t insn_word = *reinterpret_cast<const uint32_t*>(bytes);
  instruction.direct_branch = GetDirectBranchInfo(insn_word);

  // Did we expect to consume every byte?
  if (must_decode_everything && 4 != num_bytes) return false;

  // Does it look like an instruction we can use?
  absl::string_view view(
      reinterpret_cast<const char*>(instruction.encoded.begin()),
      reinterpret_cast<const char*>(instruction.encoded.end()));
  if (!StaticInstructionFilter<AArch64>(view)) return false;

  return true;
}

template <>
bool TryToReencodeInstructionDisplacements(Instruction<AArch64>& insn) {
  uint32_t* insn_word_ptr = reinterpret_cast<uint32_t*>(insn.encoded.data());
  uint32_t insn_word = *insn_word_ptr;
  for (const BranchInstructionInfo& info : kBranchInstructionInfo) {
    if (info.matcher.matches(insn_word)) {
      // Reencode the instruction
      insn_word = RewriteBranchDisplacement(
          insn_word, info.displacement.lsb, info.displacement.width,
          insn.direct_branch.encoded_byte_displacement);
      // Update the buffer.
      *insn_word_ptr = insn_word;
      // Check if the value was in bounds by re-reading the encoded value.
      return ExtractBranchDisplacement(insn_word, info.displacement.lsb,
                                       info.displacement.width) ==
             insn.direct_branch.encoded_byte_displacement;
    }
  }
  CHECK(false) << "Instruction was not a branch.";
}

}  // namespace silifuzz
