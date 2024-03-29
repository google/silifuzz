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

#include <cstdint>
#include <string>
#include <vector>

#include "gtest/gtest.h"

extern "C" {
#include "third_party/libxed/xed-address-width-enum.h"
#include "third_party/libxed/xed-decode.h"
#include "third_party/libxed/xed-decoded-inst-api.h"
#include "third_party/libxed/xed-decoded-inst.h"
#include "third_party/libxed/xed-error-enum.h"
#include "third_party/libxed/xed-machine-mode-enum.h"
}

namespace silifuzz {

namespace {

struct XedTest {
  std::string text;
  std::vector<uint8_t> bytes;
  bool not_deterministic;
  bool not_userspace;
  bool is_io;
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
          .text = "rdtsc ",
          .bytes = {0x0F, 0x31},
          .not_deterministic = true,
      },
  };
}

constexpr const uint64_t kDefaultAddress = 0x10000;

TEST(XedUtilTest, All) {
  InitXedIfNeeded();

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
      EXPECT_EQ(test.not_deterministic,
                !InstructionIsDeterministicInRunner(xedd))
          << test.text;
      EXPECT_EQ(test.not_userspace, !InstructionCanRunInUserSpace(xedd))
          << test.text;
      EXPECT_EQ(test.is_io, InstructionRequiresIOPrivileges(xedd)) << test.text;
    }
  }
}

}  // namespace

}  // namespace silifuzz
