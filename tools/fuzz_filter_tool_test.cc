// Copyright 2022 The SiliFuzz Authors.
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
//
// A SimpleFixTool is a tool the integrates the fixer pipeline, the corpus
// partitioner and relocatable corpus building. Currently, it takes a corpus
// consisting of raw instruction sequences from Centipede, converts these into
// snapshots with undefined end states, runs the Snap maker to make Snapshots
// complete, partitions snapshots into shards and creates a relocatable corpus.
// As everything is done in memory, there is a limit on of corpus size. The
// limit may change in the future if we implement streaming for intermediate
// results in and out of a file system.

#include "./tools/fuzz_filter_tool.h"

#include <stdint.h>

#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "./common/snapshot_test_config.h"

namespace silifuzz {

namespace {

std::string FromBytes(std::vector<uint8_t>&& data) {
  return std::string(data.begin(), data.end());
}

std::string FromInts(std::vector<uint32_t>&& data) {
  return std::string(reinterpret_cast<char*>(&*data.begin()),
                     reinterpret_cast<char*>(&*data.end()));
}

// Grab the instruction bytes from the snap test configs where we can.
std::string GetTestInstructions(TestSnapshot test) {
  return GetTestSnapshotConfig(Snapshot::ArchitectureTypeToEnum<Host>(), test)
      ->instruction_bytes;
}

#define EXPECT_FILTER_ACCEPT(insn) \
  EXPECT_TRUE(FilterToolMain("Test", insn).ok())

#define EXPECT_FILTER_REJECT(insn) \
  EXPECT_FALSE(FilterToolMain("Test", insn).ok())

TEST(FuzzFilterTool, Nop) {
  EXPECT_FILTER_ACCEPT(GetTestInstructions(TestSnapshot::kEndsAsExpected));
}

TEST(FuzzFilterTool, Padding) {
  EXPECT_FILTER_REJECT(GetTestInstructions(TestSnapshot::kEndsUnexpectedly));
}

TEST(FuzzFilterTool, Breakpoint) {
  EXPECT_FILTER_REJECT(GetTestInstructions(TestSnapshot::kBreakpoint));
}

TEST(FuzzFilterTool, Syscall) {
  EXPECT_FILTER_REJECT(GetTestInstructions(TestSnapshot::kSyscall));
}

#if defined(__x86_64__)

// Mostly to check that FromBytes can produce something that will be accepted.
TEST(FuzzFilterTool, NopBytes) { EXPECT_FILTER_ACCEPT(FromBytes({0x90})); }

TEST(FuzzFilterTool, JumpOutOfBounds) {
  // JMP .+0x10
  EXPECT_FILTER_REJECT(FromBytes({0xeb, 0x10}));
}

TEST(FuzzFilterTool, Int1) { EXPECT_FILTER_REJECT(FromBytes({0xf1})); }

TEST(FuzzFilterTool, Int3) {
  EXPECT_FILTER_REJECT(GetTestInstructions(TestSnapshot::kINT3_CD03));
}

TEST(FuzzFilterTool, Int80) { EXPECT_FILTER_REJECT(FromBytes({0xcd, 0x80})); }

TEST(FuzzFilterTool, UD2) {
  EXPECT_FILTER_REJECT(GetTestInstructions(TestSnapshot::kSigIll));
}

TEST(FuzzFilterTool, BlockingSyscall) {
  // read(2) from stdin
  EXPECT_FILTER_REJECT(
      FromBytes({0x48, 0x31, 0xc0, 0x48, 0x31, 0xff, 0x0f, 0x05}));
}

TEST(FuzzFilterTool, In) {
  EXPECT_FILTER_REJECT(GetTestInstructions(TestSnapshot::kIn));
}

TEST(FuzzFilterTool, Out) { EXPECT_FILTER_REJECT(FromBytes({0xef})); }

TEST(FuzzFilterTool, RDTSC) { EXPECT_FILTER_REJECT(FromBytes({0x0f, 0x31})); }

TEST(FuzzFilterTool, CPUID) { EXPECT_FILTER_REJECT(FromBytes({0x0f, 0xa2})); }

TEST(FuzzFilterTool, SLDT) {
  EXPECT_FILTER_REJECT(FromBytes({0x0f, 0x00, 0xc0}));
}

TEST(FuzzFilterTool, INC_SPLIT_LOCK) {
  EXPECT_FILTER_REJECT(FromBytes({0x48, 0x89, 0xe0, 0x48, 0xff, 0xc8, 0x30,
                                  0xc0, 0xf0, 0xff, 0x40, 0xff}));
}

#elif defined(__aarch64__)

TEST(FuzzFilterTool, ReadTPIDR) {
  // We'll want to filter our a number of system register accesses in the
  // future, but this one should stay valid.
  // mrs    x0, tpidr_el0
  EXPECT_FILTER_ACCEPT(FromInts({0xd53bd040}));
}

TEST(FuzzFilterTool, ReadCNTVCT) {
  // This should cause non-determinism.
  // mrs     x1, cntvct_el0
  EXPECT_FILTER_REJECT(FromInts({0xd53be041}));
}

TEST(FuzzFilterTool, LDXRB) {
  // The filter for store exclusive should not hit load exclusive.
  // ldxrb     w16, [x6]
  EXPECT_FILTER_ACCEPT(FromInts({0x085f7cd0}));
}

TEST(FuzzFilterTool, STR) {
  // The filter for store exclusive should not hit normal stores.
  // str     w16, [x6]
  EXPECT_FILTER_ACCEPT(FromInts({0xb90000d0}));
}

TEST(FuzzFilterTool, STXRB) {
  // Store exclusive is effectively non-deterministic.
  // stxrb     w4, w16, [x6]
  EXPECT_FILTER_REJECT(FromInts({0x080400d0}));
}

TEST(FuzzFilterTool, STXP) {
  // Store exclusive is effectively non-deterministic.
  // stxp     w11, w13, w21, [x6]
  EXPECT_FILTER_REJECT(FromInts({0x882b54cd}));
}

#endif

}  // namespace

}  // namespace silifuzz
