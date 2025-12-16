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

#include "./fuzzer/hashtest/testgeneration/instruction_pool.h"

#include <bitset>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <random>
#include <utility>
#include <vector>

#include "./fuzzer/hashtest/testgeneration/candidate.h"
#include "./fuzzer/hashtest/testgeneration/debugging.h"
#include "./fuzzer/hashtest/testgeneration/prefilter.h"
#include "./fuzzer/hashtest/testgeneration/rand_util.h"
#include "./fuzzer/hashtest/testgeneration/register_info.h"
#include "./fuzzer/hashtest/testgeneration/synthesize_base.h"
#include "./fuzzer/hashtest/testgeneration/synthesize_instruction.h"
#include "./instruction/xed_util.h"
#include "./util/checks.h"

extern "C" {
#include "third_party/libxed/xed-interface.h"
}

namespace silifuzz {

namespace {
// Determine the iform for an encoded instruction.
xed_iform_enum_t GetIForm(const uint8_t* bytes, size_t len, bool dump = false) {
  xed_state_t dstate;
  xed_state_init2(&dstate, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

  xed_decoded_inst_t decoded;
  xed_decoded_inst_zero_set_mode(&decoded, &dstate);

  CHECK_EQ(XED_ERROR_NONE, xed_decode(&decoded, bytes, len));

  if (dump) {
    std::cout << "Dumping " << len << "\n";
    std::cout << std::hex;
    for (size_t i = 0; i < len; ++i) {
      if (i > 0) {
        std::cout << " ";
      }
      std::cout << std::setfill('0') << std::setw(2) << (int)bytes[i];
    }
    std::cout << std::dec;
    std::cout << "\n";
    char buffer[4096];
    xed_decoded_inst_dump(&decoded, buffer, sizeof(buffer));
    std::cout << buffer << "\n";
  }

  return xed_decoded_inst_get_iform_enum(&decoded);
}

enum class EncodeResult {
  kOK,
  kIFormMismatch,
  kEncodeError,
};

EncodeResult TryToEncodeWidth(std::mt19937_64& rng, xed_chip_enum_t chip,
                              InstructionCandidate& candidate,
                              unsigned int effective_op_width) {
  RegisterPool base_rpool{};
  InitRegisterLayout(chip, base_rpool);

  // Note: we need try this a few times because we might stumble on a
  // "specialized" encoding with a different iform (for example a shorter
  // encoding for register AX).
  // It would be nice if we could avoid this case deterministically, but that
  // would require some sort of iform overlap analysis. Retrying here avoids a
  // bit of implementation complexity.
  for (size_t i = 0; i < 8; ++i) {
    RegisterPool rpool = base_rpool;

    // Simulate register pressure from dead registers.
    PopRandomBit(rng, rpool.entropy.gp);
    if (rpool.vec_width > 0) {
      PopRandomBit(rng, rpool.entropy.vec);
    }
    if (rpool.mask_width > 0) {
      PopRandomBit(rng, rpool.entropy.mask);
    }
    PopRandomBit(rng, rpool.entropy.mmx);
    // TODO(ncbray): reserve mix register to simulate register pressure.

    std::vector<RegisterID> needs_init;
    std::vector<unsigned int> is_written;
    uint8_t ibuf[16];
    size_t actual_len = sizeof(ibuf);

    if (!SynthesizeTestInstruction(candidate, rpool, rng, effective_op_width,
                                   needs_init, is_written, ibuf, actual_len)) {
      // This could occur if the instruction is not supported in 64-bit mode.
      return EncodeResult::kEncodeError;
    }

    if (xed_inst_iform_enum(candidate.instruction) ==
        GetIForm(ibuf, actual_len)) {
      return EncodeResult::kOK;
    }
  }

  return EncodeResult::kIFormMismatch;
}

// Statistics so we can get some sense of how instruction filtering is behaving.
struct InstructionStats {
  size_t num_iforms;
  size_t num_valid_for_chip;
  size_t num_pass_prefilter;
  size_t num_candidates;
  size_t num_encode_error;
  size_t num_iform_mismatch;
  size_t num_encoded;
  size_t num_accepted;
};

bool TryToEncode(std::mt19937_64& rng, xed_chip_enum_t chip,
                 InstructionCandidate& candidate, InstructionStats& stats,
                 bool verbose = false) {
  if (!candidate.width_16 && !candidate.width_32 && !candidate.width_64) {
    candidate.width_32 = true;
  }

  // Some iforms can mask other iforms.
  // For example a MOV_GPRv_IMMz iform can get encoded as MOV_GPRv_IMMv if the
  // effective width is not 64. (The "z" size means the immediate is 32 bits
  // when the effective width is 64.)
  bool iform_matches = false;
  for (auto& [width, width_mask] :
       std::vector<std::pair<unsigned int, bool&>>{{16, candidate.width_16},
                                                   {32, candidate.width_32},
                                                   {64, candidate.width_64}}) {
    if (width_mask) {
      switch (TryToEncodeWidth(rng, chip, candidate, width)) {
        case EncodeResult::kOK:
          iform_matches = true;
          break;
        case EncodeResult::kIFormMismatch:
          width_mask = false;
          if (verbose) {
            std::cout << "    IFORM MISMATCH " << width << "\n";
          }
          break;
        case EncodeResult::kEncodeError:
          if (verbose) {
            std::cout << "    ENCODE ERROR" << "\n";
          }
          stats.num_encode_error += 1;
          return false;
      }
    }
  }
  // If the iform didn't match for any of the effective widths but the
  // instruction was also successfully encoded, it's likely that this iform
  // requires some sort of prefix byte we don't know how to synthesize.
  // TODO(ncbray): there's evidence some of these cases are GPR8 instructions
  // that take high bytes.
  if (!iform_matches) {
    if (verbose) {
      std::cout << "    COMPLETE IFORM MISMATCH\n";
    }
    stats.num_iform_mismatch += 1;
  } else {
    stats.num_encoded += 1;
  }
  return iform_matches;
}
}  // namespace

void GenerateInstructionPool(std::mt19937_64& rng, xed_chip_enum_t chip,
                             InstructionPool& ipool, bool verbose) {
  // There may be duplicate iforms in the instruction table, so we keep track of
  // which iforms we've already seen.
  std::bitset<XED_IFORM_LAST> accepted_iforms;

  // Build the instruction pool.
  InstructionStats stats{};
  for (int i = 0; i < XED_MAX_INST_TABLE_NODES; ++i) {
    const xed_inst_t* const instruction = xed_inst_table_base() + i;

    // Is this a duplicate iform?
    xed_iform_enum_t iform = xed_inst_iform_enum(instruction);
    if (accepted_iforms.test(iform)) {
      continue;
    }
    accepted_iforms.set(iform);
    stats.num_iforms += 1;

    // Note: this only validates that the chip can run the instruction in at
    // least one operating mode. Instructions like "AAA" may be supported by the
    // chip but not in 64-bit mode.
    // TODO(ncbray): is there a way to validate the instruction is supported in
    // a specific mode other than trying to assemble it?
    if (!xed_isa_set_is_valid_for_chip(xed_inst_isa_set(instruction), chip)) {
      continue;
    }
    stats.num_valid_for_chip += 1;

    // Does this look like an instruction we want to test?
    if (!PrefilterInstruction(instruction)) {
      continue;
    }
    stats.num_pass_prefilter += 1;

    InstructionCandidate candidate{};
    if (!IsCandidate(instruction, candidate)) {
      continue;
    }
    stats.num_candidates += 1;

    // Dump information about the instruction.
    if (verbose) {
      DumpInstruction(instruction);
      std::cout << "    NODE " << i << "\n";
      std::cout << candidate.fixed_reg.read.gp.count() << "\n";
      std::cout << "RW: G(" << candidate.reg_read.gp << " / "
                << candidate.reg_written.gp << ") / V("
                << candidate.reg_read.vec << " / " << candidate.reg_written.vec
                << ") / M(" << candidate.reg_read.mask << " / "
                << candidate.reg_written.mask << " / " << candidate.writemask
                << ")\n";
      std::cout << "WIDTH: " << candidate.width_16 << " / "
                << candidate.width_32 << " / " << candidate.width_64 << "\n";
    }

    if (!TryToEncode(rng, chip, candidate, stats, verbose)) {
      continue;
    }
    stats.num_accepted += 1;

    ipool.Add(candidate);
  }

  if (verbose) {
    std::cout << "\n";
    std::cout << "Instruction Filtering" << "\n";
    std::cout << "IForms:         " << stats.num_iforms << "\n";
    std::cout << "Valid for chip: " << stats.num_valid_for_chip << "\n";
    std::cout << "Pass prefilter: " << stats.num_pass_prefilter << "\n";
    std::cout << "Candidates:     " << stats.num_candidates << "\n";
    std::cout << "Encode error:   " << stats.num_encode_error << "\n";
    std::cout << "IForm mismatch: " << stats.num_iform_mismatch << "\n";
    std::cout << "Encoded:        " << stats.num_encoded << "\n";
    std::cout << "Accepted:       " << stats.num_accepted << "\n";

    std::cout << "\n";
    std::cout << "Platform Info" << "\n";
    std::cout << "Vector width: " << ChipVectorRegisterWidth(chip) << "\n";
    std::cout << "Mask width:   " << ChipMaskRegisterWidth(chip) << "\n";

    std::cout << "\n";
    std::cout << "Instruction Categories" << "\n";
    std::cout << "No effect:         " << ipool.no_effect.size() << "\n";
    std::cout << "Flag manipulation: " << ipool.flag_manipulation.size()
              << "\n";
    std::cout << "Compare:           " << ipool.compare.size() << "\n";
    std::cout << "GPReg:             " << ipool.greg.size() << "\n";
    std::cout << "VecReg:            " << ipool.vreg.size() << "\n";
    std::cout << "MaskReg:           " << ipool.mreg.size() << "\n";
    std::cout << "MMXReg:            " << ipool.mmxreg.size() << "\n";
  }
}

}  // namespace silifuzz
