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

#include "./instruction/disassembler.h"

#include <cstdint>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_format.h"
#include "./instruction/capstone_disassembler.h"
#include "./instruction/xed_disassembler.h"
#include "./util/arch.h"

namespace silifuzz {

namespace {

using testing::HasSubstr;
using testing::StrEq;

struct DisassemblerTest {
  std::string bytes;
  std::string opcode;
  bool partial_opcode;
  bool can_branch;
  bool can_load;
  bool can_store;
};

std::string insn(uint32_t value) {
  return std::string(reinterpret_cast<char*>(&value), sizeof(value));
}

std::vector<DisassemblerTest> DisassemblerTests_X86_64() {
  return {
      {
          .bytes = {0x90},
          .opcode = "nop",
      },
      {
          .bytes = {0x51},
          .opcode = "push",
          .can_store = true,
      },
      {
          .bytes = {0x59},
          .opcode = "pop",
          .can_load = true,
      },
      {
          .bytes = {0xeb, 0x00},
          .opcode = "jmp",
          .can_branch = true,
      },
      {
          .bytes = {0xe2, 0xfe},
          .opcode = "loop",
          .can_branch = true,
      },
      {
          .bytes = {0xff, 0xd1},
          .opcode = "call",
          .partial_opcode = true,
          .can_branch = true,
          .can_store = true,
      },
      {
          .bytes = {0xc3},
          .opcode = "ret",
          .partial_opcode = true,
          .can_branch = true,
          .can_load = true,
      },
  };
}

std::vector<DisassemblerTest> DisassemblerTests_AArch64() {
  return {
      {
          .bytes = insn(0xd503201f),
          .opcode = "nop",
      },
      {
          .bytes = insn(0xa9bf07e0),
          .opcode = "stp",
          .can_store = true,
      },
      {
          .bytes = insn(0xa8c107e0),
          .opcode = "ldp",
          .can_load = true,
      },
      {
          .bytes = insn(0xb82850fe),
          .opcode = "ldsmin",
          .can_load = true,
          .can_store = true,
      },
      {
          .bytes = insn(0x14000000),
          .opcode = "b",
          .can_branch = true,
      },
      {
          .bytes = insn(0xd63f0000),
          .opcode = "blr",
          .can_branch = true,
      },
      {
          .bytes = insn(0xd65f03c0),
          .opcode = "ret",
          .can_branch = true,
      },
  };
}

enum class LoadStorePrecision {
  kPrecise,
  kCapstone_X86_64,
  kCapstone_AArch64,
};

void RunDisassemblerTest(Disassembler& disasm, const DisassemblerTest& test,
                         LoadStorePrecision lsp) {
  {
    SCOPED_TRACE(test.opcode);
    constexpr uint64_t kArbitraryAddress = 0x10000;
    ASSERT_TRUE(disasm.Disassemble(
        kArbitraryAddress, reinterpret_cast<const uint8_t*>(test.bytes.data()),
        test.bytes.size()));
  }
  SCOPED_TRACE(disasm.FullText());
  EXPECT_EQ(disasm.InstructionSize(), test.bytes.size());
  std::string opcode = disasm.InstructionIDName(disasm.InstructionID());
  if (test.partial_opcode) {
    EXPECT_THAT(opcode, HasSubstr(test.opcode));
  } else {
    EXPECT_EQ(opcode, test.opcode);
  }
  EXPECT_EQ(disasm.CanBranch(), test.can_branch);

  switch (lsp) {
    case LoadStorePrecision::kPrecise:
      EXPECT_EQ(disasm.CanLoad(), test.can_load);
      EXPECT_EQ(disasm.CanStore(), test.can_store);
      break;
    case LoadStorePrecision::kCapstone_X86_64:
      // Capstone x86_64 can miss implicit reads and writes to the stack.
      // Only assert the cases we know can't write don't write.
      if (!test.can_load) {
        EXPECT_FALSE(disasm.CanLoad());
      }
      if (!test.can_store) {
        EXPECT_FALSE(disasm.CanStore());
      }
      break;
    case LoadStorePrecision::kCapstone_AArch64:
      // Capstone aarch64 is can be wrong about loads and stores in a variety of
      // ways.
      break;
  }
}

TEST(DisassemblerTest, Xed) {
  XedDisassembler disasm;
  const std::vector<DisassemblerTest> tests = DisassemblerTests_X86_64();
  for (const DisassemblerTest& test : tests) {
    RunDisassemblerTest(disasm, test, LoadStorePrecision::kPrecise);
  }
}

TEST(DisassemblerTest, Capstone_x86_64) {
  CapstoneDisassembler<X86_64> disasm;
  const std::vector<DisassemblerTest> tests = DisassemblerTests_X86_64();
  for (const DisassemblerTest& test : tests) {
    RunDisassemblerTest(disasm, test, LoadStorePrecision::kCapstone_X86_64);
  }
}

TEST(DisassemblerTest, Capstone_AArch64) {
  CapstoneDisassembler<AArch64> disasm;
  const std::vector<DisassemblerTest> tests = DisassemblerTests_AArch64();
  for (const DisassemblerTest& test : tests) {
    RunDisassemblerTest(disasm, test, LoadStorePrecision::kCapstone_AArch64);
  }
}

TEST(DisassemblerTest, XedInvalidInstruction) {
  XedDisassembler disasm;
  DisassemblerTest invalid_x86 = {
      .bytes = {0x12, 0x34},
      .opcode = disasm.InstructionIDName(disasm.InvalidInstructionID()),
  };
  constexpr uint64_t kArbitraryAddress = 0x10000;
  EXPECT_FALSE(disasm.Disassemble(
      kArbitraryAddress,
      reinterpret_cast<const uint8_t*>(invalid_x86.bytes.data()),
      invalid_x86.bytes.size()));

  EXPECT_THAT(disasm.FullText(), StrEq("unknown 12 34"));
}

TEST(DisassemblerTest, CapstoneX86InvalidInstruction) {
  CapstoneDisassembler<X86_64> disasm;
  DisassemblerTest invalid_x86 = {
      .bytes = {0x12, 0x34},
      .opcode = disasm.InstructionIDName(disasm.InvalidInstructionID()),
  };
  constexpr uint64_t kArbitraryAddress = 0x10000;
  EXPECT_FALSE(disasm.Disassemble(
      kArbitraryAddress,
      reinterpret_cast<const uint8_t*>(invalid_x86.bytes.data()),
      invalid_x86.bytes.size()));

  EXPECT_THAT(disasm.FullText(), StrEq("unknown 12 34"));
}

TEST(DisassemblerTest, CapstoneAArch64InvalidInstruction) {
  CapstoneDisassembler<AArch64> disasm;
  DisassemblerTest invalid_arm = {
      // Taken from an invalid instruction in a snapshot.
      .bytes = {0x82, 0x84, 0x84, 0x84},
      .opcode = disasm.InstructionIDName(disasm.InvalidInstructionID()),
  };
  constexpr uint64_t kArbitraryAddress = 0x10000;
  EXPECT_FALSE(disasm.Disassemble(
      kArbitraryAddress,
      reinterpret_cast<const uint8_t*>(invalid_arm.bytes.data()),
      invalid_arm.bytes.size()));

  EXPECT_THAT(
      disasm.FullText(),
      StrEq(absl::StrFormat("unknown %08x", *reinterpret_cast<uint32_t*>(
                                                invalid_arm.bytes.data()))));
}

}  // namespace

}  // namespace silifuzz
