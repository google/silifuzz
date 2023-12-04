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

using ::fuzztest::Arbitrary;

namespace silifuzz {

namespace {

void DumpData(const uint8_t *data, size_t size) {
  for (size_t i = 0; i < size; ++i) {
    printf(" %02x", data[i]);
  }
  printf("\n");
}

void DumpProgram(const Program &program) {
  for (size_t i = 0; i < program.NumInstructions(); ++i) {
    const Instruction &insn = program.GetInstruction(i);
    printf("%03zu %04lx", i, insn.offset);
    DumpData(insn.encoded.data(), insn.encoded.size());
  }
}

constexpr const bool kPrintData = false;

void RoundtripTest(const std::vector<uint8_t> &data) {
  // Decode the random data.
  if (kPrintData) printf("from\n");
  Program program1(data, false);
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
  Program program2(first.data(), first.size(), true);
  if (kPrintData) DumpProgram(program2);

  // The second round trip should not modify anything.
  if (kPrintData) printf("to\n");
  std::vector<uint8_t> second;
  program2.ToBytes(second);
  if (kPrintData) DumpData(second.data(), second.size());
  ASSERT_EQ(first, second);
}

FUZZ_TEST(FuzzProgramMutator, RoundtripTest)
    .WithDomains(Arbitrary<std::vector<uint8_t>>());

}  // namespace

}  // namespace silifuzz
