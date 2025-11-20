// Copyright 2025 The SiliFuzz Authors.
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

#include "./fuzzer/hashtest/testgeneration/xed_operand_util.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "absl/strings/ascii.h"
#include "./fuzzer/hashtest/testgeneration/candidate.h"
#include "./fuzzer/hashtest/testgeneration/instruction_pool.h"
#include "./fuzzer/hashtest/testgeneration/prefilter.h"
#include "./instruction/xed_util.h"

extern "C" {
#include "third_party/libxed/xed-interface.h"
}

namespace silifuzz {

namespace {
TEST(XedOperandTest, TestAll) {
  InitXedIfNeeded();

  struct XedOperandResult {
    size_t operand_count = 0;

    size_t explicit_count = 0;
    size_t implicit_count = 0;
    size_t suppressed_count = 0;

    size_t reg_count = 0;
    size_t greg_count = 0;
    size_t vreg_count = 0;
    size_t mreg_count = 0;
    size_t mmxreg_count = 0;
    size_t flag_count = 0;

    size_t imm_count = 0;

    size_t xmm_count = 0;
    size_t ymm_count = 0;
    size_t zmm_count = 0;

    size_t writemask_count = 0;
  };

  const struct {
    std::string text;
    std::vector<uint8_t> bytes;
    bool filtered = false;
    XedOperandResult result;
    InstructionCandidate candidate;
  } tests[] = {
      {
          // Note: implicit flag register.
          .text = "add esi, 0x410edf37",
          .bytes = {0x81, 0xc6, 0x37, 0xdf, 0x0e, 0x41},
          .result =
              {
                  .operand_count = 3,
                  .explicit_count = 2,
                  .suppressed_count = 1,
                  .reg_count = 2,
                  .greg_count = 1,
                  .flag_count = 1,
                  .imm_count = 1,
              },
          .candidate =
              {
                  .reg_read = {.gp = 1},
                  .reg_written = {.gp = 1},
                  .fixed_reg =
                      {
                          .written = {.flags = true},
                      },
                  .vector_width = 0,
                  .width_16 = true,
                  .width_32 = true,
                  .width_64 = true,
              },
      },
      {
          // Note: A-register-specific encoding. Also note that implicit
          // operands are not accounted for the same way as explicit ones - this
          // is not a "greg".
          .text = "add al, 0xee",
          .bytes = {0x04, 0xee},
          .result =
              {
                  .operand_count = 3,
                  .explicit_count = 1,
                  .implicit_count = 1,
                  .suppressed_count = 1,
                  .reg_count = 2,
                  .greg_count = 0,
                  .flag_count = 1,
                  .imm_count = 1,
              },
          .candidate =
              {
                  .reg_read = {.gp = 1},
                  .reg_written = {.gp = 1},
                  .fixed_reg =
                      {
                          .written = {.flags = true},
                      },
              },
      },
      {
          .text = "vaddps ymm1, ymm13, ymm15",
          .bytes = {0xc4, 0xc1, 0x14, 0x58, 0xcf},
          .result =
              {
                  .operand_count = 3,
                  .explicit_count = 3,
                  .reg_count = 3,
                  .vreg_count = 3,
                  .ymm_count = 3,
              },
          .candidate =
              {
                  .reg_read = {.vec = 2},
                  .reg_written = {.vec = 1},
                  .vector_width = 256,
              },
      },
      {
          // Note: explicit k0 writemask is omitted from disassembly.
          .text = "vaddpd zmm3, zmm9, zmm14",
          .bytes = {0x62, 0xd1, 0xb5, 0x48, 0x58, 0xde},
          .result =
              {
                  .operand_count = 4,
                  .explicit_count = 4,
                  .reg_count = 4,
                  .vreg_count = 3,
                  .mreg_count = 1,
                  .zmm_count = 3,
                  .writemask_count = 1,
              },
          .candidate =
              {
                  .reg_read = {.vec = 2, .mask = 1},
                  .reg_written = {.vec = 1},
                  .vector_width = 512,
                  .writemask = true,
              },
      },
      {
          .text = "kmovq k1, r14",
          .bytes = {0xc4, 0xc1, 0xfb, 0x92, 0xce},
          .result =
              {
                  .operand_count = 2,
                  .explicit_count = 2,
                  .reg_count = 2,
                  .greg_count = 1,
                  .mreg_count = 1,
              },
          .candidate =
              {
                  .reg_read = {.gp = 1},
                  .reg_written = {.mask = 1},
              },
      },
      {
          .text = "psrlw mm0, 0x8a",
          .bytes = {0x0f, 0x71, 0xd0, 0x8a},
          .result =
              {
                  .operand_count = 2,
                  .explicit_count = 2,
                  .reg_count = 1,
                  .mmxreg_count = 1,
                  .imm_count = 1,
              },
          .candidate =
              {
                  .reg_read = {.mmx = 1},
                  .reg_written = {.mmx = 1},
              },
      },
      {
          .text = "cmovnz rax, rbx",
          .bytes = {0x48, 0x0f, 0x45, 0xc3},
          .result =
              {
                  .operand_count = 3,
                  .explicit_count = 2,
                  .suppressed_count = 1,
                  .reg_count = 3,
                  .greg_count = 2,
                  .flag_count = 1,
              },
          .candidate =
              {
                  // Note: the conditional output means the output register is
                  // effectively an input.
                  .reg_read = {.gp = 2},
                  .reg_written = {.gp = 1},
                  .fixed_reg =
                      {
                          .read = {.flags = true},
                      },
                  .width_16 = true,
                  .width_32 = true,
                  .width_64 = true,
              },
      },
      {
          .text = "nop",
          .bytes = {0x90},
          .filtered = true,
          .result = {},
      },
      {
          .text = "int3",
          .bytes = {0xcc},
          .filtered = true,
          .result =
              {
                  // XED says int3 reads and writes flags and writes RIP.
                  .operand_count = 2,
                  .suppressed_count = 2,
                  .reg_count = 2,
                  .flag_count = 1,
              },
      },
  };

  constexpr uint64_t kDefaultAddress = 0x10000;

  // Temp buffer for FormatInstruction.
  char text[96];

  InstructionPool ipool{};
  for (const auto& test : tests) {
    // Disassemble the bytes.
    xed_decoded_inst_t xedd;
    xed_decoded_inst_zero(&xedd);
    xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LONG_64,
                              XED_ADDRESS_WIDTH_64b);
    xed_error_enum_t decode_result =
        xed_decode(&xedd, test.bytes.data(), test.bytes.size());
    EXPECT_EQ(decode_result, XED_ERROR_NONE) << test.text;
    if (decode_result != XED_ERROR_NONE) {
      continue;
    }

    // Check the text matches the disassembly.
    bool formatted =
        FormatInstruction(xedd, kDefaultAddress, text, sizeof(text));
    EXPECT_TRUE(formatted) << test.text;
    if (!formatted) {
      continue;
    }
    EXPECT_EQ(absl::StripAsciiWhitespace(text), test.text) << test.text;

    const xed_inst_t* instruction = xed_decoded_inst_inst(&xedd);
    EXPECT_EQ(test.filtered, !PrefilterInstruction(instruction)) << test.text;

    InstructionCandidate candidate{};
    if (!test.filtered) {
      EXPECT_EQ(true, IsCandidate(instruction, candidate)) << test.text;
      EXPECT_EQ(candidate.instruction, instruction);
    }
    EXPECT_EQ(candidate.reg_read.gp, test.candidate.reg_read.gp) << test.text;
    EXPECT_EQ(candidate.reg_written.gp, test.candidate.reg_written.gp)
        << test.text;
    EXPECT_EQ(candidate.reg_read.vec, test.candidate.reg_read.vec) << test.text;
    EXPECT_EQ(candidate.reg_written.vec, test.candidate.reg_written.vec)
        << test.text;
    EXPECT_EQ(candidate.reg_read.mask, test.candidate.reg_read.mask)
        << test.text;
    EXPECT_EQ(candidate.reg_written.mask, test.candidate.reg_written.mask)
        << test.text;
    EXPECT_EQ(candidate.reg_read.mmx, test.candidate.reg_read.mmx) << test.text;
    EXPECT_EQ(candidate.reg_written.mmx, test.candidate.reg_written.mmx)
        << test.text;
    EXPECT_EQ(candidate.fixed_reg.read.flags,
              test.candidate.fixed_reg.read.flags)
        << test.text;
    EXPECT_EQ((int)candidate.fixed_reg.written.flags,
              (int)test.candidate.fixed_reg.written.flags)
        << test.text;

    EXPECT_EQ(candidate.vector_width, test.candidate.vector_width) << test.text;
    EXPECT_EQ(candidate.width_16, test.candidate.width_16) << test.text;
    EXPECT_EQ(candidate.width_32, test.candidate.width_32) << test.text;
    EXPECT_EQ(candidate.width_64, test.candidate.width_64) << test.text;
    EXPECT_EQ(candidate.writemask, test.candidate.writemask) << test.text;

    // Scan the operands.
    XedOperandResult result = {};
    for (size_t operand_index = 0;
         operand_index < xed_inst_noperands(instruction); ++operand_index) {
      const xed_operand_t* const operand =
          xed_inst_operand(instruction, operand_index);
      result.operand_count++;

      if (OperandIsExplicit(operand)) {
        result.explicit_count++;
      }
      if (OperandIsImplicit(operand)) {
        result.implicit_count++;
      }
      if (OperandIsSuppressed(operand)) {
        result.suppressed_count++;
      }

      if (OperandIsRegister(operand)) {
        result.reg_count++;
      }
      if (OperandIsGPRegister(operand)) {
        result.greg_count++;
      }
      if (OperandIsVectorRegister(operand)) {
        result.vreg_count++;
      }
      if (OperandIsMaskRegister(operand)) {
        result.mreg_count++;
      }
      if (OperandIsMMXRegister(operand)) {
        result.mmxreg_count++;
      }
      if (OperandIsFlagRegister(operand)) {
        result.flag_count++;
      }
      if (OperandIsImmediate(operand)) {
        result.imm_count++;
      }

      if (OperandIsXMMRegister(operand)) {
        result.xmm_count++;
      }
      if (OperandIsYMMRegister(operand)) {
        result.ymm_count++;
      }
      if (OperandIsZMMRegister(operand)) {
        result.zmm_count++;
      }

      if (OperandIsWritemask(operand)) {
        result.writemask_count++;
      }
    }

    EXPECT_EQ(result.operand_count, test.result.operand_count) << test.text;

    EXPECT_EQ(result.explicit_count, test.result.explicit_count) << test.text;
    EXPECT_EQ(result.implicit_count, test.result.implicit_count) << test.text;
    EXPECT_EQ(result.suppressed_count, test.result.suppressed_count)
        << test.text;

    EXPECT_EQ(result.reg_count, test.result.reg_count) << test.text;
    EXPECT_EQ(result.greg_count, test.result.greg_count) << test.text;
    EXPECT_EQ(result.vreg_count, test.result.vreg_count) << test.text;
    EXPECT_EQ(result.mreg_count, test.result.mreg_count) << test.text;
    EXPECT_EQ(result.mmxreg_count, test.result.mmxreg_count) << test.text;
    EXPECT_EQ(result.flag_count, test.result.flag_count) << test.text;

    EXPECT_EQ(result.imm_count, test.result.imm_count) << test.text;

    EXPECT_EQ(result.xmm_count, test.result.xmm_count) << test.text;
    EXPECT_EQ(result.ymm_count, test.result.ymm_count) << test.text;
    EXPECT_EQ(result.zmm_count, test.result.zmm_count) << test.text;

    EXPECT_EQ(result.writemask_count, test.result.writemask_count) << test.text;

    ipool.Add(candidate);
  }

  EXPECT_EQ(ipool.no_effect.size(), 2);
  EXPECT_EQ(ipool.flag_manipulation.size(), 0);
  EXPECT_EQ(ipool.compare.size(), 0);
  EXPECT_EQ(ipool.greg.size(), 3);
  EXPECT_EQ(ipool.vreg.size(), 2);
  EXPECT_EQ(ipool.mreg.size(), 1);
  EXPECT_EQ(ipool.mmxreg.size(), 1);

  ipool = ipool.Filter([](const InstructionCandidate& candidate) {
    // Filter out 256 bit vector instructions (YMM registers).
    return candidate.vector_width != 256;
  });

  EXPECT_EQ(ipool.no_effect.size(), 2);
  EXPECT_EQ(ipool.flag_manipulation.size(), 0);
  EXPECT_EQ(ipool.compare.size(), 0);
  EXPECT_EQ(ipool.greg.size(), 3);
  EXPECT_EQ(ipool.vreg.size(), 1);  // ymm filtered out.
  EXPECT_EQ(ipool.mreg.size(), 1);
  EXPECT_EQ(ipool.mmxreg.size(), 1);
}

}  // namespace

}  // namespace silifuzz
