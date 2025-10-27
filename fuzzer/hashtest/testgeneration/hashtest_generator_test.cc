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
#include <functional>
#include <random>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/ascii.h"
#include "./fuzzer/hashtest/testgeneration/candidate.h"
#include "./fuzzer/hashtest/testgeneration/instruction_pool.h"
#include "./fuzzer/hashtest/testgeneration/prefilter.h"
#include "./fuzzer/hashtest/testgeneration/rand_util.h"
#include "./fuzzer/hashtest/testgeneration/register_info.h"
#include "./fuzzer/hashtest/testgeneration/synthesize_base.h"
#include "./fuzzer/hashtest/testgeneration/synthesize_shuffle.h"
#include "./fuzzer/hashtest/testgeneration/weighted_choose_one.h"
#include "./fuzzer/hashtest/testgeneration/xed_operand_util.h"
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

TEST(RandUtil, RandomElementVec) {
  std::mt19937_64 rng(0);
  std::vector<int> v = {7};
  EXPECT_EQ(7, ChooseRandomElement(rng, v));
}

TEST(RandUtil, RandomElementInitList) {
  std::mt19937_64 rng(0);
  EXPECT_EQ(11, ChooseRandomElement(rng, {11}));
}

TEST(WeightedChooseOne, Single) {
  std::mt19937_64 rng(0);
  size_t a = 0;
  constexpr size_t kNumIter = 40000;
  for (size_t i = 0; i < kNumIter; i++) {
    EXPECT_EQ(WeightedChooseOne(rng,
                                WeightedChoice{
                                    1,
                                    [&] {
                                      a += 1;
                                      return 11;
                                    },
                                }),
              11);
  }
  EXPECT_EQ(a, kNumIter);
}

TEST(WeightedChooseOne, Zero) {
  std::mt19937_64 rng(0);
  size_t a = 0;
  size_t b = 0;
  constexpr size_t kNumIter = 40000;
  for (size_t i = 0; i < kNumIter; i++) {
    WeightedChooseOne(rng,
                      // A
                      WeightedChoice{
                          1,
                          [&] { a += 1; },
                      },
                      // B
                      WeightedChoice{
                          0,
                          [&] { b += 1; },
                      });
  }
  EXPECT_EQ(a, kNumIter);
  EXPECT_EQ(b, 0);
}

TEST(WeightedChooseOne, CheckWeights) {
  std::mt19937_64 rng(0);
  size_t a = 0;
  size_t b = 0;
  size_t c = 0;
  size_t d = 0;
  constexpr size_t kNumIter = 40000;
  constexpr int kAWeight = 1;
  constexpr int kBWeight = 2;
  constexpr int kCWeight = 3;
  constexpr int kDWeight = 4;
  constexpr int kTotalWeight = kAWeight + kBWeight + kCWeight + kDWeight;
  for (size_t i = 0; i < kNumIter; i++) {
    WeightedChooseOne(rng,
                      // A
                      WeightedChoice{
                          kAWeight,
                          [&] { a += 1; },
                      },
                      // B
                      WeightedChoice{
                          kBWeight,
                          [&] { b += 1; },
                      },
                      // C
                      WeightedChoice{
                          kCWeight,
                          [&] { c += 1; },
                      },
                      // D
                      WeightedChoice{
                          kDWeight,
                          [&] { d += 1; },
                      });
  }
  // Assert that we are not more than 5% off the expected distribution.
  // It's questionable to test random behavior, but this is somewhat forgiven
  // by having a fixed seed.
  constexpr auto lower_limit = [&](int weight) -> size_t {
    return kNumIter * weight * 95 / 100 / kTotalWeight;
  };
  EXPECT_GE(a, lower_limit(kAWeight));
  EXPECT_GE(b, lower_limit(kBWeight));
  EXPECT_GE(c, lower_limit(kCWeight));
  EXPECT_GE(d, lower_limit(kDWeight));
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

TEST(SynthesizeShuffleTest, RandomPermutationMask) {
  Rng rng(0);
  // Generate a bunch of random permutation masks and make sure they match
  // expected invariant.
  constexpr size_t num_bits = 2;
  constexpr size_t num_elements = 1 << num_bits;
  for (size_t i = 0; i < 1000; i++) {
    size_t mask = RandomPermutationMask<num_bits>(rng);
    bool elements[num_elements] = {};
    // Verify that each element of the mask is unique.
    // Note this also (indirectly) verifies that each element is present because
    // if they aren't all present, at least one will be non-unique.
    for (size_t i = 0; i < num_elements; i++) {
      size_t index = mask & (num_elements - 1);
      EXPECT_FALSE(elements[index]) << index;
      elements[index] = true;
      mask >>= num_bits;
    }
    // Make sure no more bits of the mask are set.
    EXPECT_EQ(mask, 0);
  }
}

void TestShuffleFunc(
    std::function<void(Rng&, RegisterPool&, InstructionBlock&)>&& f) {
  Rng rng(0);

  // Sweep through different vector widths.
  for (size_t vec_width = 128; vec_width <= 512; vec_width *= 2) {
    RegisterPool base_rpool{};
    // Treat all registers as temporary.
    base_rpool.tmp.gp.set();
    if (vec_width >= 512) {
      base_rpool.tmp.vec.set();
    } else {
      // There are only 16 vector registers if the machine does not have AVX512.
      for (size_t i = 0; i < 16; ++i) {
        base_rpool.tmp.vec.set(i);
      }
    }
    base_rpool.tmp.mask.set();
    base_rpool.tmp.mmx.set();

    base_rpool.vec_width = vec_width;
    // Sweep through different mask widths.
    for (size_t mask_width = 16; mask_width <= 64; mask_width *= 2) {
      base_rpool.mask_width = mask_width;

      // Since the function we are testing is random, it's hard to precisely
      // define the expected behavior. Instead, we just run it a bunch of times
      // with different parameters and make sure it doesn't crash.
      for (size_t i = 0; i < 200; ++i) {
        RegisterPool rpool = base_rpool;
        InstructionBlock block{};
        f(rng, rpool, block);

        // Check that something was emitted.
        EXPECT_GE(block.num_instructions, 1);
        EXPECT_GE(block.bytes.size(), 1);

        // But not too much.
        EXPECT_LE(block.num_instructions, 5);
        EXPECT_LE(block.bytes.size(), 30);
      }
    }
  }
}

TEST(SynthesizeShuffleTest, GPRegPermute) {
  TestShuffleFunc([](Rng& rng, RegisterPool& rpool, InstructionBlock& block) {
    SynthesizeGPRegPermute(rng, PopRandomBit(rng, rpool.tmp.gp), block);
  });
}

TEST(SynthesizeShuffleTest, GPRegMix) {
  TestShuffleFunc([](Rng& rng, RegisterPool& rpool, InstructionBlock& block) {
    SynthesizeGPRegMix(rng, PopRandomBit(rng, rpool.tmp.gp),
                       PopRandomBit(rng, rpool.tmp.gp), block);
  });
}

TEST(SynthesizeShuffleTest, VecRegPermute) {
  TestShuffleFunc([](Rng& rng, RegisterPool& rpool, InstructionBlock& block) {
    SynthesizeVecRegPermute(rng, PopRandomBit(rng, rpool.tmp.vec),
                            PopRandomBit(rng, rpool.tmp.vec), rpool, block);
  });
}

TEST(SynthesizeShuffleTest, VecRegMix) {
  TestShuffleFunc([](Rng& rng, RegisterPool& rpool, InstructionBlock& block) {
    SynthesizeVecRegMix(rng, PopRandomBit(rng, rpool.tmp.vec),
                        PopRandomBit(rng, rpool.tmp.vec),
                        PopRandomBit(rng, rpool.tmp.vec), rpool, block);
  });
}

TEST(SynthesizeShuffleTest, MaskRegPermute) {
  TestShuffleFunc([](Rng& rng, RegisterPool& rpool, InstructionBlock& block) {
    SynthesizeMaskRegPermute(rng, PopRandomBit(rng, rpool.tmp.mask),
                             PopRandomBit(rng, rpool.tmp.mask), rpool, block);
  });
}

TEST(SynthesizeShuffleTest, MaskRegMix) {
  TestShuffleFunc([](Rng& rng, RegisterPool& rpool, InstructionBlock& block) {
    SynthesizeMaskRegMix(rng, PopRandomBit(rng, rpool.tmp.mask),
                         PopRandomBit(rng, rpool.tmp.mask),
                         PopRandomBit(rng, rpool.tmp.mask), rpool, block);
  });
}

TEST(SynthesizeShuffleTest, MMXRegPermute) {
  TestShuffleFunc([](Rng& rng, RegisterPool& rpool, InstructionBlock& block) {
    SynthesizeMMXRegPermute(rng, PopRandomBit(rng, rpool.tmp.mmx),
                            PopRandomBit(rng, rpool.tmp.mmx), RandomBool(rng),
                            block);
  });
}

TEST(SynthesizeShuffleTest, MMXRegMix) {
  TestShuffleFunc([](Rng& rng, RegisterPool& rpool, InstructionBlock& block) {
    SynthesizeMMXRegMix(rng, PopRandomBit(rng, rpool.tmp.mmx),
                        PopRandomBit(rng, rpool.tmp.mmx), block);
  });
}

}  // namespace

}  // namespace silifuzz
