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

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <vector>

#include "gtest/gtest.h"
#include "./fuzzer/program.h"
#include "./fuzzer/program_arch.h"
#include "./fuzzer/program_mutation_ops.h"

namespace silifuzz {

namespace {

TEST(MutatorUtil, RandomIndex) {
  MutatorRng rng(0);

  size_t min = std::numeric_limits<size_t>::max();
  size_t max = std::numeric_limits<size_t>::min();

  for (size_t i = 0; i < 10000; ++i) {
    size_t value = RandomIndex(rng, 4);
    min = std::min(min, value);
    max = std::max(max, value);
  }

  EXPECT_EQ(min, 0);
  EXPECT_EQ(max, 3);
}

TEST(MutatorUtil, RandomInstructionIndex) {
  // 3 NOPs
  std::vector<uint8_t> bytes = {0x90, 0x90, 0x90};
  Program p(bytes.data(), bytes.size(), true);

  MutatorRng rng(0);

  size_t min = std::numeric_limits<size_t>::max();
  size_t max = std::numeric_limits<size_t>::min();

  for (size_t i = 0; i < 10000; ++i) {
    size_t value = p.RandomInstructionIndex(rng);
    min = std::min(min, value);
    max = std::max(max, value);
  }

  EXPECT_EQ(min, 0);
  EXPECT_EQ(max, p.NumInstructions() - 1);
}

TEST(MutatorUtil, RandomInstructionBoundary) {
  // 3 NOPs
  std::vector<uint8_t> bytes = {0x90, 0x90, 0x90};
  Program p(bytes.data(), bytes.size(), true);

  MutatorRng rng(0);

  size_t min = std::numeric_limits<size_t>::max();
  size_t max = std::numeric_limits<size_t>::min();

  for (size_t i = 0; i < 10000; ++i) {
    size_t value = p.RandomInstructionBoundary(rng);
    min = std::min(min, value);
    max = std::max(max, value);
  }

  EXPECT_EQ(min, 0);
  EXPECT_EQ(max, p.NumInstructionBoundaries() - 1);
}

TEST(MutatorUtil, RandomInstructionBoundaryEmpty) {
  // Empty program
  std::vector<uint8_t> bytes = {};
  Program p(bytes.data(), bytes.size(), true);

  MutatorRng rng(0);

  size_t min = std::numeric_limits<size_t>::max();
  size_t max = std::numeric_limits<size_t>::min();

  for (size_t i = 0; i < 10000; ++i) {
    size_t value = p.RandomInstructionBoundary(rng);
    min = std::min(min, value);
    max = std::max(max, value);
  }

  EXPECT_EQ(min, 0);
  EXPECT_EQ(max, p.NumInstructionBoundaries() - 1);
}

TEST(MutatorUtil, FlipBit) {
  uint64_t buffer;
  for (size_t i = 0; i < sizeof(buffer) * 8; ++i) {
    buffer = 0ULL;

    // Flip on.
    FlipBit(reinterpret_cast<uint8_t*>(&buffer), i);
    EXPECT_EQ(buffer, 1ULL << i);

    // Flip off.
    FlipBit(reinterpret_cast<uint8_t*>(&buffer), i);
    EXPECT_EQ(buffer, 0ULL);

    // Show it works fine with other non-zero bits.
    buffer = ~0ULL;

    // Flip off.
    FlipBit(reinterpret_cast<uint8_t*>(&buffer), i);
    EXPECT_EQ(buffer, ~(1ULL << i));

    // Flip on.
    FlipBit(reinterpret_cast<uint8_t*>(&buffer), i);
    EXPECT_EQ(buffer, ~0ULL);
  }
}

TEST(MutatorUtil, FlipRandomBit) {
  // Fixed seed for deterministic test.
  MutatorRng rng(0);

  for (size_t range = 1; range <= 4; range++) {
    uint64_t all_bits = 0;
    for (size_t i = 0; i < 10000; ++i) {
      uint64_t buffer = 0;
      // Only flip bits in the lower `range` bytes.
      FlipRandomBit(rng, reinterpret_cast<uint8_t*>(&buffer), range);
      all_bits |= buffer;
    }
    // Did we flip every bit in the target bytes?
    EXPECT_EQ(all_bits, (1ULL << (range * 8)) - 1) << range;
  }
}

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

TEST(InstructionFromBytes_X86_64, NonCanonicalJNS) {
  std::vector<uint8_t> bytes = {0x41, 0x79, 0xfc};
  Instruction instruction;
  EXPECT_TRUE(InstructionFromBytes(bytes.data(), bytes.size(), instruction));
  EXPECT_EQ(instruction.encoded.size(), 3);
  EXPECT_TRUE(instruction.direct_branch.valid());
  EXPECT_EQ(instruction.direct_branch.encoded_byte_displacement, -1);

  EXPECT_TRUE(TryToReencodeInstructionDisplacements(instruction));
  // Should be canonicalized.
  EXPECT_EQ(instruction.encoded.size(), 2);
  EXPECT_TRUE(instruction.direct_branch.valid());
  EXPECT_EQ(instruction.direct_branch.encoded_byte_displacement, -1);
  EXPECT_EQ(instruction.encoded.data()[0], 0x79);
  // Displacement shorter because instruction shorter.
  EXPECT_EQ(instruction.encoded.data()[1], 0xfd);

  // Change the displacement.
  instruction.direct_branch.encoded_byte_displacement = 0;
  EXPECT_TRUE(TryToReencodeInstructionDisplacements(instruction));
  EXPECT_EQ(instruction.encoded.size(), 2);
  EXPECT_TRUE(instruction.direct_branch.valid());
  EXPECT_EQ(instruction.direct_branch.encoded_byte_displacement, 0);
  EXPECT_EQ(instruction.encoded.data()[0], 0x79);
  EXPECT_EQ(instruction.encoded.data()[1], 0xfe);
}

std::vector<uint8_t> ToBytes(Program& program) {
  MutatorRng rng;
  program.FixupEncodedDisplacements(rng);

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
    EXPECT_FALSE(insn.direct_branch.valid());
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
    EXPECT_FALSE(insn.direct_branch.valid());
    EXPECT_EQ(insn.direct_branch.instruction_boundary,
              kInvalidInstructionBoundary);
  }

  {
    const Instruction& insn = p.GetInstruction(1);
    EXPECT_EQ(insn.encoded.size(), 1);
    EXPECT_EQ(insn.encoded.data()[0], 0xc3);
    EXPECT_FALSE(insn.direct_branch.valid());
    EXPECT_EQ(insn.direct_branch.instruction_boundary,
              kInvalidInstructionBoundary);
  }

  EXPECT_EQ(ToBytes(p), bytes);
}

TEST(Program_X86_64, InsertEmpty) {
  std::vector<uint8_t> bytes = {};
  Program p(bytes.data(), bytes.size(), true);

  // Create NOP instruction.
  std::vector<uint8_t> nop = {0x90};
  Instruction insn{};
  insn.encoded.Copy(nop.data(), nop.size());

  for (bool steal : {false, true}) {
    Program mut = p;
    mut.InsertInstruction(0, steal, insn);
    mut.CheckConsistency();
    EXPECT_EQ(ToBytes(mut), std::vector<uint8_t>({0x90})) << steal;
    mut.CheckConsistency();
  }
}

// The end of the program is an instruction "boundary" that isn't a valid
// instruction "index". This creates a corner case for stealing and non-stealing
// inserts.
TEST(Program_X86_64, InsertAroundBranchToEnd) {
  // JBE to the end of the program.
  std::vector<uint8_t> bytes = {0x76, 0x00};
  Program p(bytes.data(), bytes.size(), true);

  // Create NOP instruction.
  std::vector<uint8_t> nop = {0x90};
  Instruction insn{};
  insn.encoded.Copy(nop.data(), nop.size());

  {
    Program mut = p;
    // Non-stealing insert.
    mut.InsertInstruction(1, false, insn);
    mut.CheckConsistency();
    EXPECT_EQ(ToBytes(mut), std::vector<uint8_t>({0x76, 0x01, 0x90}));
    mut.CheckConsistency();
  }

  {
    Program mut = p;
    // Stealing insert.
    mut.InsertInstruction(1, true, insn);
    mut.CheckConsistency();
    EXPECT_EQ(ToBytes(mut), std::vector<uint8_t>({0x76, 0x00, 0x90}));
    mut.CheckConsistency();
  }
}

TEST(Program_X86_64, InsertNearBranch) {
  // JBE that jumps to itself, followed by JA that jumps to itself
  std::vector<uint8_t> bytes = {0x76, 0xfe, 0x77, 0xfe};
  Program p(bytes.data(), bytes.size(), true);

  // Check bytes are interpreted as expected.
  constexpr size_t kNumInstructions = 2;
  ASSERT_EQ(p.NumInstructions(), kNumInstructions);
  for (size_t i = 0; i < kNumInstructions; ++i) {
    const Instruction& insn = p.GetInstruction(i);
    EXPECT_EQ(insn.encoded.size(), 2);
    EXPECT_TRUE(insn.direct_branch.valid());
    EXPECT_EQ(insn.direct_branch.encoded_byte_displacement, 0);
    EXPECT_EQ(insn.direct_branch.instruction_boundary, i);
  }

  // Can recover original program.
  EXPECT_EQ(ToBytes(p), bytes);
  p.CheckConsistency();

  // Create NOP instruction.
  std::vector<uint8_t> nop = {0x90};
  Instruction insn{};
  insn.encoded.Copy(nop.data(), nop.size());

  struct InsertTest {
    size_t index;
    bool steal;
    std::vector<uint8_t> result;
  } tests[] = {
      {0, false, {0x90, 0x76, 0xfe, 0x77, 0xfe}},
      {0, true, {0x90, 0x76, 0xfd, 0x77, 0xfe}},
      {1, false, {0x76, 0xfe, 0x90, 0x77, 0xfe}},
      {1, true, {0x76, 0xfe, 0x90, 0x77, 0xfd}},
      {2, false, {0x76, 0xfe, 0x77, 0xfe, 0x90}},
      {2, true, {0x76, 0xfe, 0x77, 0xfe, 0x90}},
  };

  for (const InsertTest& test : tests) {
    Program mut = p;
    mut.InsertInstruction(test.index, test.steal, insn);
    mut.CheckConsistency();
    EXPECT_EQ(ToBytes(mut), test.result) << test.index << " " << test.steal;
    mut.CheckConsistency();
  }
}

TEST(Program_X86_64, RemoveNearBranch) {
  // JNE, JBE, then JA.
  // JNE jumps to end.
  // JBE jumps to beginning.
  // JA jumps to JBE.
  std::vector<uint8_t> bytes = {0x75, 0x04, 0x76, 0xfc, 0x77, 0xfc};
  Program p(bytes.data(), bytes.size(), true);

  // Check bytes are interpreted as expected.
  constexpr size_t kNumInstructions = 3;
  ASSERT_EQ(p.NumInstructions(), kNumInstructions);
  for (size_t i = 0; i < kNumInstructions; ++i) {
    const Instruction& insn = p.GetInstruction(i);
    EXPECT_EQ(insn.encoded.size(), 2);
    EXPECT_TRUE(insn.direct_branch.valid());
  }

  // Can recover original program.
  EXPECT_EQ(ToBytes(p), bytes);
  p.CheckConsistency();

  struct RemoveTest {
    size_t index;
    std::vector<uint8_t> result;
  } tests[] = {
      {0, {0x76, 0xfe, 0x77, 0xfc}},
      {1, {0x75, 0x02, 0x77, 0xfe}},
      {2, {0x75, 0x02, 0x76, 0xfc}},
  };

  for (const RemoveTest& test : tests) {
    Program mut = p;
    mut.RemoveInstruction(test.index);
    mut.CheckConsistency();
    EXPECT_EQ(ToBytes(mut), test.result) << test.index;
    mut.CheckConsistency();
  }
}

TEST(Program_X86_64, OutOfRangeBranch) {
  // JNE to the end of the program.
  std::vector<uint8_t> bytes = {0x75, 0x00};
  Program p(bytes.data(), bytes.size(), true);

  ASSERT_EQ(p.NumInstructions(), 1);

  {
    const Instruction& insn = p.GetInstruction(0);
    EXPECT_EQ(insn.encoded.size(), 2);
    EXPECT_TRUE(insn.direct_branch.valid());
    EXPECT_EQ(insn.direct_branch.instruction_boundary, 1);
  }

  // A non-branch instruction that's not tiny.
  // vpaddd ymm14, ymm6, ymm7
  std::vector<uint8_t> filler_bytes = {0xc5, 0x4d, 0xfe, 0xf7};

  Instruction filler{};
  ASSERT_TRUE(InstructionFromBytes(filler_bytes.data(), filler_bytes.size(),
                                   filler, true));

  // Add instructions to stretch the branch out.
  for (size_t i = 0; i < 250; i++) {
    // This is not a stealing insert, so the branch to the end of the program
    // should stay pointing to the end of the program.
    p.InsertInstruction(p.NumInstructions(), false, filler);
  }

  EXPECT_EQ(p.GetInstruction(0).direct_branch.instruction_boundary,
            p.NumInstructions());

  // Force re-writing of the instructions.
  ToBytes(p);

  // The instruction index was out of range, so it should have be randomized to
  // an in-range value.
  {
    const Instruction& insn = p.GetInstruction(0);

    EXPECT_NE(insn.direct_branch.instruction_boundary, p.NumInstructions());
    // A larger negative displacement would land before the program.
    EXPECT_GE(insn.direct_branch.encoded_byte_displacement, 0);
    // A larger positive displacement could not be encoded.
    EXPECT_LE(insn.direct_branch.encoded_byte_displacement, 2 + 128);
  }
}

TEST(Program_X86_64, UnmodifiedNonCanonicalJNS) {
  // This is a jump with an unused rex.B prefix.
  // It decodes, but if it's rewritten the prefix disappears.
  //  1000000:    41 79 fd     rex.B jns 0x1000000
  std::vector<uint8_t> bytes = {0x41, 0x79, 0xfd};
  Program p(bytes.data(), bytes.size(), true);
  ASSERT_EQ(p.NumInstructions(), 1);

  {
    const Instruction& insn = p.GetInstruction(0);
    EXPECT_EQ(insn.encoded.size(), 3);
    EXPECT_TRUE(insn.direct_branch.valid());
    EXPECT_EQ(insn.direct_branch.encoded_byte_displacement, 0);
    EXPECT_EQ(insn.direct_branch.instruction_boundary, 0);
  }

  // An canonical branch that doesn't need to be written stays canonical.
  EXPECT_EQ(ToBytes(p), bytes);
}

TEST(Program_X86_64, ModifiedNonCanonicalJNS) {
  // This non-canonical instruction jumps 1 byte before itself.
  // The displacement is slightly off to force re-encoding and therefore force
  // canonicalization.
  std::vector<uint8_t> bytes = {0x41, 0x79, 0xfc};
  Program p(bytes.data(), bytes.size(), false);
  ASSERT_EQ(p.NumInstructions(), 1);

  {
    const Instruction& insn = p.GetInstruction(0);
    EXPECT_EQ(insn.encoded.size(), 3);
    EXPECT_TRUE(insn.direct_branch.valid());
    EXPECT_EQ(insn.direct_branch.encoded_byte_displacement, -1);
    EXPECT_EQ(insn.direct_branch.instruction_boundary, 0);
  }

  // Converting this program back to bytes is a bit of a stress test because it
  // must iterate.
  // 1) the byte displacement does not match the instruction index, so the
  // branch is rewritten.
  // 2) rewriting the branch canonicalizes the instruction, which makes it
  // shorter. Since the branch displacement is from the end of the instruction,
  // making the instruction shorter means the byte displacement still does not
  // match the instruction index. So the branch needs to be rewritten again.
  // The end result should be a JNS that jumps to itself.
  std::vector<uint8_t> expected = {0x79, 0xfe};
  EXPECT_EQ(ToBytes(p), expected);
}

TEST(Program_X86_64, ModifiedNonCanonicalJNSCrosslink) {
  // A non-canonical JNS that jumps to the end of the program followed by a
  // NOP followed by a non-canonical JNS that jumps to the beginning of the
  // program.
  std::vector<uint8_t> bytes = {0x41, 0x79, 0x04, 0x90, 0x41, 0x79, 0xf9};
  Program p(bytes.data(), bytes.size(), true);
  ASSERT_EQ(p.NumInstructions(), 3);

  {
    const Instruction& insn = p.GetInstruction(0);
    EXPECT_EQ(insn.encoded.size(), 3);
    EXPECT_TRUE(insn.direct_branch.valid());
    EXPECT_EQ(insn.direct_branch.encoded_byte_displacement, 7);
    EXPECT_EQ(insn.direct_branch.instruction_boundary, 3);
  }

  {
    const Instruction& insn = p.GetInstruction(1);
    EXPECT_EQ(insn.encoded.size(), 1);
    EXPECT_FALSE(insn.direct_branch.valid());
  }

  {
    const Instruction& insn = p.GetInstruction(2);
    EXPECT_EQ(insn.encoded.size(), 3);
    EXPECT_TRUE(insn.direct_branch.valid());
    EXPECT_EQ(insn.direct_branch.encoded_byte_displacement, -4);
    EXPECT_EQ(insn.direct_branch.instruction_boundary, 0);
  }

  // Removing the NOP causes the JNS instructions to be re-encoded.
  // Re-encoding the JNS instructions causes canonicalization.
  // Canonicalization of the JNS instruction changes their size, and therefore
  // affects the encoded displacements.
  // This test checks that changing the size of one instruction affects the
  // displacement of the other.
  p.RemoveInstruction(1);

  std::vector<uint8_t> expected = {0x79, 0x02, 0x79, 0xfc};
  EXPECT_EQ(ToBytes(p), expected);
}

}  // namespace

}  // namespace silifuzz
