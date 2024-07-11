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

#include <bitset>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <iomanip>
#include <iostream>
#include <random>
#include <utility>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/check.h"
#include "./fuzzer/hashtest/candidate.h"
#include "./fuzzer/hashtest/debugging.h"
#include "./fuzzer/hashtest/prefilter.h"
#include "./fuzzer/hashtest/rand_util.h"
#include "./fuzzer/hashtest/register_info.h"
#include "./fuzzer/hashtest/synthesize_instruction.h"
#include "./instruction/xed_util.h"
#include "./util/checks.h"
#include "./util/enum_flag_types.h"
#include "./util/itoa.h"
#include "./util/platform.h"

extern "C" {
#include "third_party/libxed/xed-interface.h"
}

ABSL_FLAG(silifuzz::PlatformId, platform, silifuzz::PlatformId::kUndefined,
          "Platform to target.");

namespace silifuzz {

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

constexpr unsigned int kLoopIndex = 8;

// Mark which registers are: 1) temporary values, 2) entropy values, and 3)
// should not be used when generating tests.
void InitRegisterLayout(xed_chip_enum_t chip, RegisterPool& rpool) {
  rpool.vec_width = ChipVectorRegisterWidth(chip);
  rpool.mask_width = ChipMaskRegisterWidth(chip);

  // GP registers.
  const unsigned int stack_index = XedRegToRegisterID(XED_REG_RSP).index;
  for (int i = 0; i < rpool.tmp.gp.size(); ++i) {
    if (i == kLoopIndex) {
      // Iteration reg.
    } else if (i == stack_index) {
      // Stack pointer.
    } else if (i >= 9 && i < 16) {
      // Use higher registers for entropy since the lower registers may be fixed
      // read/write targets for some instructions.
      rpool.entropy.gp[i] = true;
    } else {
      rpool.tmp.gp[i] = true;
    }
  }

  // Vector registers.
  // TODO(ncbray): when is this 16 registers vs. 32?
  for (int i = 0; i < rpool.tmp.vec.size(); ++i) {
    // Entropy needs to be initializable by Silifuzz.
    if (i >= 8 && i < 16) {
      // Use higher registers for entropy since the XMM0 may be a fixed
      // read/write target for some instructions.
      rpool.entropy.vec[i] = true;
    } else if (i >= 16) {
      // Extended registers.
    } else {
      rpool.tmp.vec[i] = true;
    }
  }

  // Mask registers.
  for (int i = 0; i < rpool.tmp.mask.size(); ++i) {
    if (i >= 4 && i < 8) {
      // k0 cannot be an entropy register because it has a special meaning when
      // used as a write mask.
      rpool.entropy.mask[i] = true;
    } else {
      rpool.tmp.mask[i] = true;
    }
  }

  // MMX registers.
  for (int i = 0; i < rpool.tmp.mmx.size(); ++i) {
    if (i >= 4 && i < 8) {
      rpool.entropy.mmx[i] = true;
    } else {
      rpool.tmp.mmx[i] = true;
    }
  }
}

// A set of instructions we can use for generating tests, grouped by which
// register bank they affect.
struct InstructionPool {
  std::vector<InstructionCandidate> no_effect;
  std::vector<InstructionCandidate> flag_manipulation;
  std::vector<InstructionCandidate> compare;
  std::vector<InstructionCandidate> greg;
  std::vector<InstructionCandidate> vreg;
  std::vector<InstructionCandidate> mreg;
  std::vector<InstructionCandidate> mmxreg;

  void Add(const InstructionCandidate& candidate) {
    if (candidate.reg_written.gp) {
      greg.push_back(candidate);
    } else if (candidate.reg_written.vec) {
      vreg.push_back(candidate);
    } else if (candidate.reg_written.mask) {
      mreg.push_back(candidate);
    } else if (candidate.reg_written.mmx) {
      mmxreg.push_back(candidate);
    } else if (candidate.fixed_reg.written.flags) {
      if (candidate.reg_read.Total() > 0) {
        compare.push_back(candidate);
      } else {
        flag_manipulation.push_back(candidate);
      }
    } else {
      no_effect.push_back(candidate);
    }
  }
};

enum class EncodeResult {
  kOK,
  kIFormMismatch,
  kEncodeError,
};

EncodeResult TryToEncodeWidth(Rng& rng, xed_chip_enum_t chip,
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
    PopRandomBit(rng, rpool.entropy.vec);
    PopRandomBit(rng, rpool.entropy.mask);
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

bool TryToEncode(Rng& rng, xed_chip_enum_t chip,
                 InstructionCandidate& candidate, InstructionStats& stats) {
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
          std::cout << "    IFORM MISMATCH " << width << "\n";
          break;
        case EncodeResult::kEncodeError:
          std::cout << "    ENCODE ERROR" << "\n";
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
    std::cout << "    COMPLETE IFORM MISMATCH\n";
    stats.num_iform_mismatch += 1;
  } else {
    stats.num_encoded += 1;
  }
  return iform_matches;
}

int ToolMain(std::vector<char*> positional_args) {
  // Initialize XED.
  xed_tables_init();

  // Determine which platform to target.
  PlatformId platform = absl::GetFlag(FLAGS_platform);
  xed_chip_enum_t chip = PlatformIdToChip(platform);
  QCHECK_NE(chip, XED_CHIP_INVALID)
      << "Unsupported platform: " << EnumStr(platform);

  // Initialize the RNG.
  std::random_device rd;
  Rng rng(rd());

  // There may be duplicate iforms in the instruction table, so we keep track of
  // which iforms we've already seen.
  std::bitset<XED_IFORM_LAST> accepted_iforms;

  // Build the instruction pool.
  InstructionPool ipool{};
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
    DumpInstruction(instruction);
    std::cout << "    NODE " << i << "\n";
    std::cout << candidate.fixed_reg.read.gp.count() << "\n";
    std::cout << "RW: G(" << candidate.reg_read.gp << " / "
              << candidate.reg_written.gp << ") / V(" << candidate.reg_read.vec
              << " / " << candidate.reg_written.vec << ") / M("
              << candidate.reg_read.mask << " / " << candidate.reg_written.mask
              << " / " << candidate.writemask << ")\n";
    std::cout << "WIDTH: " << candidate.width_16 << " / " << candidate.width_32
              << " / " << candidate.width_64 << "\n";

    if (!TryToEncode(rng, chip, candidate, stats)) {
      continue;
    }
    stats.num_accepted += 1;

    ipool.Add(candidate);
  }
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
  std::cout << "Flag manipulation: " << ipool.flag_manipulation.size() << "\n";
  std::cout << "Compare:           " << ipool.compare.size() << "\n";
  std::cout << "GReg:              " << ipool.greg.size() << "\n";
  std::cout << "VReg:              " << ipool.vreg.size() << "\n";
  std::cout << "MReg:              " << ipool.mreg.size() << "\n";
  std::cout << "MMXReg:            " << ipool.mmxreg.size() << "\n";

  return 0;
}

}  // namespace silifuzz

int main(int argc, char* argv[]) {
  std::vector<char*> positional_args = absl::ParseCommandLine(argc, argv);
  return silifuzz::ToolMain(positional_args);
}