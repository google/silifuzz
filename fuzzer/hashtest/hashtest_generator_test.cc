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
#include <cstddef>
#include <cstdint>
#include <random>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/ascii.h"
#include "./fuzzer/hashtest/prefilter.h"
#include "./fuzzer/hashtest/rand_util.h"
#include "./fuzzer/hashtest/register_info.h"
#include "./fuzzer/hashtest/xed_operand_util.h"
#include "./instruction/xed_util.h"

extern "C" {
#include "third_party/libxed/xed-interface.h"
}

namespace silifuzz {

namespace {

using ::testing::UnorderedElementsAre;

TEST(RandUtil, SingleRandomBit) {
  std::mt19937_64 rng(0);
  constexpr size_t kNumBits = 100;
  for (size_t i = 0; i < kNumBits; ++i) {
    std::bitset<kNumBits> bits;
    bits.set(i);
    EXPECT_TRUE(bits.any());
    EXPECT_EQ(i, ChooseRandomBit(rng, bits));
    EXPECT_TRUE(bits.any());
    EXPECT_EQ(i, PopRandomBit(rng, bits));
    EXPECT_FALSE(bits.any());
  }
}

TEST(RandUtil, MultipleRandomBits) {
  std::mt19937_64 rng(0);
  constexpr size_t kNumBits = 100;
  std::bitset<kNumBits> bits;
  bits.set(11);
  bits.set(13);
  bits.set(53);
  bits.set(97);
  std::vector<size_t> popped_bits;
  while (bits.any()) {
    popped_bits.push_back(PopRandomBit(rng, bits));
  }
  EXPECT_THAT(popped_bits, UnorderedElementsAre(11, 13, 53, 97));
}

TEST(RandUtil, RandomElement) {
  std::mt19937_64 rng(0);
  std::vector<int> v = {7};
  EXPECT_EQ(7, ChooseRandomElement(rng, v));
}

TEST(RegisterInfo, RegisterTranslation) {
  // HACK to get number of registers in each bank.
  RegisterMask m{};

  // General purpose registers.
  for (unsigned int i = 0; i < m.gp.size(); ++i) {
    RegisterID original{.bank = RegisterBank::kGP, .index = i};
    for (size_t width : {8, 16, 32, 64}) {
      RegisterID roundtrip =
          XedRegToRegisterID(RegisterIDToXedReg(original, width));
      EXPECT_EQ(roundtrip, original);
    }
  }

  // Vector registers.
  for (unsigned int i = 0; i < m.vec.size(); ++i) {
    RegisterID original{.bank = RegisterBank::kVec, .index = i};
    for (size_t width : {128, 256, 512}) {
      RegisterID roundtrip =
          XedRegToRegisterID(RegisterIDToXedReg(original, width));
      EXPECT_EQ(roundtrip, original);
    }
  }

  // MMX registers.
  for (unsigned int i = 0; i < m.mmx.size(); ++i) {
    RegisterID original{.bank = RegisterBank::kMMX, .index = i};
    for (size_t width : {64}) {
      RegisterID roundtrip =
          XedRegToRegisterID(RegisterIDToXedReg(original, width));
      EXPECT_EQ(roundtrip, original);
    }
  }
}

TEST(RegisterInfo, NonterminalTranslation) {
  EXPECT_EQ(
      XED_REG_RAX,
      RegisterIDToXedReg(XedNonterminalToRegisterID(XED_NONTERMINAL_ORAX), 64));

  EXPECT_EQ(
      XED_REG_RDX,
      RegisterIDToXedReg(XedNonterminalToRegisterID(XED_NONTERMINAL_ORDX), 64));
}

TEST(RegisterInfo, CountEmpty) {
  RegisterMask m{};
  EXPECT_EQ(m.Count().Total(), 0);
}

TEST(RegisterInfo, CountFlags) {
  // Flags are not part of a register bank, so they are not counted.
  // This is a little strange, but code elsewhere depends on this behavior so
  // test it to confirm this is the behavior.
  RegisterMask m{};
  m.flags = true;
  EXPECT_EQ(m.Count().Total(), 0);
}

TEST(RegisterInfo, RegisterMask) {
  constexpr RegisterBank kBanks[] = {RegisterBank::kGP, RegisterBank::kVec,
                                     RegisterBank::kMask, RegisterBank::kMMX};
  for (RegisterBank bank1 : kBanks) {
    for (RegisterBank bank2 : kBanks) {
      RegisterMask m{};

      RegisterID id1{.bank = bank1, .index = 0};
      RegisterID id2{.bank = bank2, .index = 1};

      // Set registers.
      m.Set(id1, true);
      m.Set(id2, true);

      // Check registers were set.
      EXPECT_TRUE(m.Get(id1));
      EXPECT_TRUE(m.Get(id2));

      // Count set registers.
      RegisterCount count = m.Count();
      EXPECT_EQ(count.Total(), 2);
      size_t expected_count = bank1 == bank2 ? 2 : 1;
      EXPECT_EQ(count.Get(bank1), expected_count);
      EXPECT_EQ(count.Get(bank2), expected_count);

      // Unset the registers.
      m.Clear(id1);
      m.Clear(id2);

      // Check registers were unset.
      EXPECT_FALSE(m.Get(id1));
      EXPECT_FALSE(m.Get(id2));

      // Count to make sure everything is empty.
      count = m.Count();
      EXPECT_EQ(count.Total(), 0);
      EXPECT_EQ(count.Get(bank1), 0);
      EXPECT_EQ(count.Get(bank2), 0);
    }
  }
}

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
    EXPECT_EQ(absl::StripAsciiWhitespace(test.text), test.text) << test.text;

    const xed_inst_t* instruction = xed_decoded_inst_inst(&xedd);
    EXPECT_EQ(test.filtered, !PrefilterInstruction(instruction)) << test.text;

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
  }
}

}  // namespace

}  // namespace silifuzz
