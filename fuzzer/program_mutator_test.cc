// Copyright 2023 The Silifuzz Authors.
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

#include <cstdint>
#include <cstring>
#include <vector>

#include "gtest/gtest.h"
#include "./fuzzer/program.h"
#include "./fuzzer/program_arch.h"

namespace silifuzz {

namespace {

TEST(InstructionFromBytes_X86_64, Copy) {
  uint8_t buffer[kInsnBufferSize];
  memset(buffer, 0xff, sizeof(buffer));
  buffer[sizeof(buffer) - 1] = 0xa5;

  InstructionData data;
  data.Copy(buffer, sizeof(buffer));
  ASSERT_EQ(data.size(), kInsnBufferSize);
  EXPECT_EQ(data.data()[data.size() - 1], 0xa5);
}

TEST(InstructionFromBytes_X86_64, CopyDeathTest) {
  uint8_t buffer[kInsnBufferSize + 1];
  memset(buffer, 0xff, sizeof(buffer));

  InstructionData data;
  ASSERT_DEATH({ data.Copy(buffer, sizeof(buffer)); }, "");
}

TEST(InstructionFromBytes_X86_64, Junk) {
  std::vector<uint8_t> bytes = {0xff, 0xff};
  Instruction instruction;
  EXPECT_FALSE(InstructionFromBytes(bytes.data(), bytes.size(), instruction));
  // Did not decode.
  EXPECT_EQ(instruction.encoded.size(), 0);
}

TEST(InstructionFromBytes_X86_64, NOP) {
  std::vector<uint8_t> bytes = {0x90};
  Instruction instruction;
  EXPECT_TRUE(InstructionFromBytes(bytes.data(), bytes.size(), instruction));
  EXPECT_EQ(instruction.encoded.size(), 1);
}

TEST(InstructionFromBytes_X86_64, RDTSC) {
  std::vector<uint8_t> bytes = {0x0f, 0x31};
  Instruction instruction;
  EXPECT_FALSE(InstructionFromBytes(bytes.data(), bytes.size(), instruction));
  // Even when the instruction was rejected, we see its size.
  EXPECT_EQ(instruction.encoded.size(), 2);
}

std::vector<uint8_t> ToBytes(Program& program) {
  std::vector<uint8_t> out;
  program.ToBytes(out);
  return out;
}

TEST(Program_X86_64, Empty) {
  std::vector<uint8_t> bytes = {};
  Program p(bytes.data(), bytes.size(), true);
  ASSERT_EQ(p.NumInstructions(), 0);

  EXPECT_EQ(ToBytes(p), bytes);
}

TEST(Program_X86_64, NOP) {
  std::vector<uint8_t> bytes = {0x90};
  Program p(bytes.data(), bytes.size(), true);
  ASSERT_EQ(p.NumInstructions(), 1);

  {
    const Instruction& insn = p.GetInstruction(0);
    EXPECT_EQ(insn.encoded.size(), 1);
    EXPECT_EQ(insn.encoded.data()[0], 0x90);
  }

  EXPECT_EQ(ToBytes(p), bytes);
}

TEST(Program_X86_64, JunkIgnored) {
  std::vector<uint8_t> bytes = {0x90, 0xff, 0x90};
  Program p(bytes.data(), bytes.size(), false);
  ASSERT_EQ(p.NumInstructions(), 2);

  std::vector<uint8_t> expected = {0x90, 0x90};
  EXPECT_EQ(ToBytes(p), expected);
}

TEST(Program_X86_64, StrictDeathTest) {
  std::vector<uint8_t> bytes = {0x90, 0xff, 0x90};
  ASSERT_DEATH({ Program p(bytes.data(), bytes.size(), true); }, "");
}

TEST(Program_X86_64, NOP_RET) {
  std::vector<uint8_t> bytes = {0x90, 0xc3};
  Program p(bytes.data(), bytes.size(), true);
  ASSERT_EQ(p.NumInstructions(), 2);

  {
    const Instruction& insn = p.GetInstruction(0);
    EXPECT_EQ(insn.encoded.size(), 1);
    EXPECT_EQ(insn.encoded.data()[0], 0x90);
  }

  {
    const Instruction& insn = p.GetInstruction(1);
    EXPECT_EQ(insn.encoded.size(), 1);
    EXPECT_EQ(insn.encoded.data()[0], 0xc3);
  }

  EXPECT_EQ(ToBytes(p), bytes);
}

}  // namespace

}  // namespace silifuzz
