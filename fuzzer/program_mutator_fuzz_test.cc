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

// This is a stress test for the Silifuzz mutator to help find corner cases.

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <vector>

#include "gtest/gtest.h"
#include "fuzztest/fuzztest.h"
#include "./fuzzer/program.h"
#include "./fuzzer/program_mutation_ops.h"
#include "./util/arch.h"

using ::fuzztest::Arbitrary;

namespace silifuzz {

namespace {

void DumpData(const uint8_t *data, size_t size) {
  for (size_t i = 0; i < size; ++i) {
    printf(" %02x", data[i]);
  }
  printf("\n");
}

template <typename Arch>
void DumpProgram(const Program<Arch> &program) {
  for (size_t i = 0; i < program.NumInstructions(); ++i) {
    const Instruction<Arch> &insn = program.GetInstruction(i);
    printf("%03zu %04lx", i, insn.offset);
    DumpData(insn.encoded.data(), insn.encoded.size());
  }
}

constexpr const bool kPrintData = false;

template <typename Arch>
void RoundtripTest(uint64_t seed, const std::vector<uint8_t> &data) {
  MutatorRng rng(seed);
  InstructionConfig config = {};

  // Decode the random data.
  if (kPrintData) printf("from\n");
  Program<Arch> program1(data, config, false);
  if (kPrintData) DumpProgram(program1);

  // Re-encode the instructions with fixed-up displacements.
  if (kPrintData) printf("rewrite\n");
  program1.FixupEncodedDisplacements(rng);
  if (kPrintData) DumpProgram(program1);

  // Regenerate the bytes from the parsed, re-encoded instructions.
  if (kPrintData) printf("to\n");
  std::vector<uint8_t> first;
  program1.ToBytes(first);
  if (kPrintData) DumpData(first.data(), first.size());
  // The bytes may look quite a bit different than the original data, but it
  // should never be larger.
  ASSERT_LE(first.size(), data.size());

  // Re-parse the serialized program - it should parse perfectly.
  if (kPrintData) printf("from\n");
  Program<Arch> program2(first.data(), first.size(), config, true);
  if (kPrintData) DumpProgram(program2);

  // This should be a no-op.
  if (kPrintData) printf("rewrite\n");
  ASSERT_FALSE(program2.FixupEncodedDisplacements(rng));
  if (kPrintData) DumpProgram(program2);

  // The second round trip should not modify anything.
  if (kPrintData) printf("to\n");
  std::vector<uint8_t> second;
  program2.ToBytes(second);
  if (kPrintData) DumpData(second.data(), second.size());
  ASSERT_EQ(first, second);
}

// Needed to work around FUZZ_TEST macro limitations.
void RoundtripTest_X86_64(uint64_t seed, const std::vector<uint8_t> &data) {
  RoundtripTest<X86_64>(seed, data);
}

// Needed to work around FUZZ_TEST macro limitations.
void RoundtripTest_AArch64(uint64_t seed, const std::vector<uint8_t> &data) {
  RoundtripTest<AArch64>(seed, data);
}

template <typename Arch>
void MutationTest(uint64_t seed, const std::vector<uint8_t> &data) {
  MutatorRng rng(seed);
  InstructionConfig config = {};

  Program<Arch> program(data, config, false);

  // Do a mixture of mutation operations so that we have a decently-sized
  // program.
  for (size_t i = 0; i < 2000; ++i) {
    InsertRandomInstruction(rng, program);
  }

  for (size_t i = 0; i < 1000; ++i) {
    MutateRandomInstruction(rng, program);
  }

  for (size_t i = 0; i < 200; ++i) {
    RemoveRandomInstruction(rng, program);
  }

  program.CheckConsistency();

  program.FixupEncodedDisplacements(rng);

  std::vector<uint8_t> first;
  program.ToBytes(first);

  Program<Arch> reparse(first, config, true);
  EXPECT_EQ(program.NumInstructions(), reparse.NumInstructions());

  // Nothing to fixup.
  EXPECT_FALSE(reparse.FixupEncodedDisplacements(rng));

  // Make sure the generated program can roundtrip.
  std::vector<uint8_t> second;
  reparse.ToBytes(second);
  EXPECT_EQ(first, second);
}

// Needed to work around FUZZ_TEST macro limitations.
void MutationTest_X86_64(uint64_t seed, const std::vector<uint8_t> &data) {
  MutationTest<X86_64>(seed, data);
}

// Needed to work around FUZZ_TEST macro limitations.
void MutationTest_AArch64(uint64_t seed, const std::vector<uint8_t> &data) {
  MutationTest<AArch64>(seed, data);
}

template <typename Arch>
void MaxLenTest(uint64_t seed, const std::vector<uint8_t> &data) {
  MutatorRng rng(seed);
  InstructionConfig config = {};

  Program<Arch> program(data, config, false);

  // Generate a random program.
  for (size_t i = 0; i < 1000; ++i) {
    InsertRandomInstruction(rng, program);
  }

  // This should canonicalize most branches.
  program.FixupEncodedDisplacements(rng);

  size_t max_len = rng() % 200;

  // The program will always be too large.
  EXPECT_GT(program.ByteLen(), max_len);
  EXPECT_TRUE(LimitProgramLength(rng, program, max_len));
  program.FixupEncodedDisplacements(rng);

  std::vector<uint8_t> limited;
  program.ToBytes(limited);

  // The program is under the limit.
  EXPECT_LE(limited.size(), max_len);

  // The program is one instruction or less under the limit.
  // Note: this test is a little shaky because re-canonicalization after
  // limiting the length could drop the size more than expected.
  // However, since the instructions are purely random the first fixup should
  // canonicalize most of the instructions. It is also unlikely that the last
  // instruction removed was the maximum possible size for an instruction.
  EXPECT_GT(limited.size() + kInstructionInfo<Arch>.max_size, max_len);
}

// Needed to work around FUZZ_TEST macro limitations.
void MaxLenTest_X86_64(uint64_t seed, const std::vector<uint8_t> &data) {
  MaxLenTest<X86_64>(seed, data);
}

// Needed to work around FUZZ_TEST macro limitations.
void MaxLenTest_AArch64(uint64_t seed, const std::vector<uint8_t> &data) {
  MaxLenTest<AArch64>(seed, data);
}

FUZZ_TEST(FuzzProgramMutator, RoundtripTest_X86_64)
    .WithDomains(Arbitrary<uint64_t>(), Arbitrary<std::vector<uint8_t>>());

FUZZ_TEST(FuzzProgramMutator, RoundtripTest_AArch64)
    .WithDomains(Arbitrary<uint64_t>(), Arbitrary<std::vector<uint8_t>>());

FUZZ_TEST(FuzzProgramMutator, MutationTest_X86_64)
    .WithDomains(Arbitrary<uint64_t>(), Arbitrary<std::vector<uint8_t>>());

FUZZ_TEST(FuzzProgramMutator, MutationTest_AArch64)
    .WithDomains(Arbitrary<uint64_t>(), Arbitrary<std::vector<uint8_t>>());

FUZZ_TEST(FuzzProgramMutator, MaxLenTest_X86_64)
    .WithDomains(Arbitrary<uint64_t>(), Arbitrary<std::vector<uint8_t>>());

FUZZ_TEST(FuzzProgramMutator, MaxLenTest_AArch64)
    .WithDomains(Arbitrary<uint64_t>(), Arbitrary<std::vector<uint8_t>>());

}  // namespace

}  // namespace silifuzz
