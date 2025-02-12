// Copyright 2023 The SiliFuzz Authors.
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

#include "./instruction/xed_util.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "./util/itoa.h"
#include "./util/platform.h"

extern "C" {
#include "third_party/libxed/xed-interface.h"
}

namespace silifuzz {

namespace {

class XedUtilTest : public testing::Test {
 protected:
  // Every test will need XED to be initialized.
  // It's easier to do this in SetUp rather than remember to add this to every
  // test.
  void SetUp() override { InitXedIfNeeded(); }
};

struct XedTest {
  std::string text;
  std::vector<uint8_t> bytes;
  bool not_deterministic;
  bool not_userspace;
  bool is_branch;
  bool is_io;
  bool is_sse;
  bool is_x87;
};

std::vector<XedTest> MakeXedTests() {
  // TODO(ncbray): why does XED put spaces at the end of some of these ops?
  return {
      {
          .text = "nop",
          .bytes = {0x90},
      },
      {
          .text = "hlt",
          .bytes = {0xf4},
          .not_userspace = true,
      },
      {
          .text = "invlpg byte ptr [rdi]",
          .bytes = {0x0f, 0x01, 0x3f},
          .not_userspace = true,
      },
      {
          .text = "lidt ptr [0x0]",
          .bytes = {0x2e, 0x0f, 0x01, 0x1c, 0x25, 0x00, 0x00, 0x00, 0x00},
          .not_userspace = true,
      },
      {
          .text = "mov rcx, cr2",
          .bytes = {0x0f, 0x20, 0xd1},
          .not_userspace = true,
      },
      {
          .text = "rdmsr ",
          .bytes = {0x0f, 0x32},
          .not_deterministic = true,
          .not_userspace = true,
      },
      {
          .text = "in eax, dx",
          .bytes = {0xed},
          .is_io = true,
      },
      {
          .text = "rep outsb ",
          .bytes = {0xf3, 0x6e},
          .is_io = true,
      },
      {
          .text = "ret ",
          .bytes = {0xc3},
          .is_branch = true,
      },
      {
          .text = "rdtsc ",
          .bytes = {0x0F, 0x31},
          .not_deterministic = true,
      },
      {
          .text = "addpd xmm6, xmm1",
          .bytes = {0x66, 0x0F, 0x58, 0xf1},
          .is_sse = true,
      },
      {
          .text = "fcos ",
          .bytes = {0xd9, 0xff},
          .is_x87 = true,
      },
      {
          .text = "movnti qword ptr [rdi], rax",
          .bytes = {0x48, 0x0f, 0xc3, 0x07},
          .is_sse = true,
      },
  };
}

constexpr const uint64_t kDefaultAddress = 0x10000;

TEST_F(XedUtilTest, InstructionPredicates) {
  char text[96];

  std::vector<XedTest> tests = MakeXedTests();
  for (const XedTest& test : tests) {
    xed_decoded_inst_t xedd;
    xed_decoded_inst_zero(&xedd);
    xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LONG_64,
                              XED_ADDRESS_WIDTH_64b);
    bool valid = xed_decode(&xedd, test.bytes.data(), test.bytes.size()) ==
                 XED_ERROR_NONE;
    EXPECT_TRUE(valid) << test.text;
    if (valid) {
      bool formatted =
          FormatInstruction(xedd, kDefaultAddress, text, sizeof(text));
      EXPECT_TRUE(formatted) << test.text;
      if (formatted) {
        EXPECT_STREQ(text, test.text.c_str()) << test.text;
      }
      const xed_inst_t* instruction = xed_decoded_inst_inst(&xedd);
      EXPECT_EQ(test.not_deterministic,
                !InstructionClassIsAllowedInRunner(instruction))
          << test.text;
      EXPECT_EQ(test.not_userspace, !InstructionCanRunInUserSpace(instruction))
          << test.text;
      EXPECT_EQ(test.is_branch, InstructionIsBranch(instruction)) << test.text;
      EXPECT_EQ(test.is_io, InstructionRequiresIOPrivileges(instruction))
          << test.text;
      EXPECT_EQ(!test.not_deterministic && !test.is_io && !test.not_userspace,
                InstructionIsAllowedInRunner(instruction))
          << test.text;
      EXPECT_EQ(test.is_sse, InstructionIsSSE(instruction)) << test.text;
      EXPECT_EQ(test.is_x87, InstructionIsX87(instruction)) << test.text;
    }
  }
}

TEST_F(XedUtilTest, ChipInfo) {
  struct {
    PlatformId platform;
    xed_chip_enum_t chip;
    unsigned int vector_width;
    unsigned int mask_width;
  } chips[] = {
      {PlatformId::kIntelIvybridge, XED_CHIP_IVYBRIDGE, 128, 0},
      {PlatformId::kIntelBroadwell, XED_CHIP_BROADWELL, 256, 0},
      {PlatformId::kIntelSkylake, XED_CHIP_SKYLAKE_SERVER, 512, 64},
      {PlatformId::kIntelSapphireRapids, XED_CHIP_SAPPHIRE_RAPIDS, 512, 64},
      {PlatformId::kAmdRome, XED_CHIP_AMD_ZEN2, 256, 0},
  };

  for (const auto& info : chips) {
    SCOPED_TRACE(EnumStr(info.platform));
    EXPECT_EQ(PlatformIdToChip(info.platform), info.chip);
    EXPECT_EQ(ChipVectorRegisterWidth(info.chip), info.vector_width);
    EXPECT_EQ(ChipMaskRegisterWidth(info.chip), info.mask_width);
  }
}

TEST_F(XedUtilTest, InstructionBuilder) {
  // Generate a simple instruction.
  InstructionBuilder builder(XED_ICLASS_DEC, 64U);
  builder.AddOperands(xed_reg(XED_REG_R8));

  uint8_t buf[16];
  size_t size = sizeof(buf);
  ASSERT_TRUE(builder.Encode(buf, size));

  // Try to decode the generated instruction.
  xed_decoded_inst_t xedd;
  xed_decoded_inst_zero(&xedd);
  xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LONG_64,
                            XED_ADDRESS_WIDTH_64b);
  ASSERT_EQ(xed_decode(&xedd, buf, size), XED_ERROR_NONE);
  EXPECT_EQ(xed_decoded_inst_get_iclass(&xedd), XED_ICLASS_DEC);

  // Check the formatted text.
  char text[96];
  ASSERT_TRUE(FormatInstruction(xedd, kDefaultAddress, text, sizeof(text)));
  EXPECT_STREQ(text, "dec r8");
}

}  // namespace

}  // namespace silifuzz
