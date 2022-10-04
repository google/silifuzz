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

#include <endian.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "gtest/gtest.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

namespace {

static int run_bytes(std::vector<uint8_t>&& data) {
  return LLVMFuzzerTestOneInput(data.data(), data.size());
}

static int run_instructions(std::vector<uint32_t>&& data) {
  // Instructions should be little endian.
  for (size_t i = 0; i < data.size(); ++i) {
    data[i] = htole32(data[i]);
  }
  return LLVMFuzzerTestOneInput(reinterpret_cast<const uint8_t *>(data.data()),
                                data.size() * sizeof(uint32_t));
}

// The preprocessor does not understand initializer lists, so hack around this
// with vardic macros.
#define EXPECT_BYTES_ACCEPTED(...) EXPECT_EQ(0, run_bytes(__VA_ARGS__));
#define EXPECT_BYTES_REJECTED(...) EXPECT_EQ(-1, run_bytes(__VA_ARGS__));
#define EXPECT_INSTRUCTIONS_ACCEPTED(...) \
  EXPECT_EQ(0, run_instructions(__VA_ARGS__));
#define EXPECT_INSTRUCTIONS_REJECTED(...) \
  EXPECT_EQ(-1, run_instructions(__VA_ARGS__));

TEST(UnicornAarch64, Empty) {
  // Zero-length input should be rejected.
  EXPECT_INSTRUCTIONS_REJECTED({});
}

TEST(UnicornAarch64, CompleteInstruction) {
  // Only accept an input if the size is a multiple of 4.
  // 72b0c000        movk    w0, #0x8600, lsl #16
  EXPECT_BYTES_REJECTED({0x00, 0xc0, 0xb0});
  EXPECT_BYTES_ACCEPTED({0x00, 0xc0, 0xb0, 0x72});
  EXPECT_BYTES_REJECTED({0x00, 0xc0, 0xb0, 0x72, 0x00});
}

TEST(UnicornAarch64, MultipleInstructions) {
  // b0b0b0c0        adrp    x0, 0xffffffff62619000
  // f2194e39        ands    x25, x17, #0x7ffff8007ffff80
  // ca5a2735        eor     x21, x25, x26, lsr #9
  EXPECT_INSTRUCTIONS_ACCEPTED({0xb0b0b0c0, 0xf2194e39, 0xca5a2735});
}

TEST(UnicornAarch64, UDF) {
  // UDF should fault.
  EXPECT_INSTRUCTIONS_REJECTED({0x00000000});
}

TEST(UnicornAarch64, InfiniteLoop) {
  // Jump to the same instruction.
  // 14000000  b <beginning of this instruction>
  EXPECT_INSTRUCTIONS_REJECTED({0x14000000});

  // Two instruction loop.
  // 14000001  b <next>
  // 17ffffff  b <begin>
  EXPECT_INSTRUCTIONS_REJECTED({0x14000001, 0x17ffffff});
}

TEST(UnicornAarch64, TrivialBranch) {
  // Jump to the next instruction.
  // 14000001  b <end of this instruction>
  EXPECT_INSTRUCTIONS_ACCEPTED({0x14000001});

  // This will be an infinite loop if we don't skip the second instruction.
  // 14000002  b <end>
  // 17ffffff  b <begin>
  EXPECT_INSTRUCTIONS_ACCEPTED({0x14000002, 0x17ffffff});
}

TEST(UnicornAarch64, OutOfBounds) {
  // Jump one instruction after the next one.
  // 14000002  b <1 after>
  EXPECT_INSTRUCTIONS_REJECTED({0x14000002});

  // Jump one instruction before this one.
  // 17ffffff  b <1 before>
  EXPECT_INSTRUCTIONS_REJECTED({0x17ffffff});
}

}  // namespace
