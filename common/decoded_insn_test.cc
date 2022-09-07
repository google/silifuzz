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

#include "./common/decoded_insn.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/ascii.h"

namespace silifuzz {
namespace {

TEST(DecodedInsn, Nop) {
  DecodedInsn insn("\x90");
  ASSERT_TRUE(insn.is_valid());
  EXPECT_EQ(absl::StripAsciiWhitespace(insn.DebugString()), "nop");
  EXPECT_TRUE(insn.is_deterministic());
  EXPECT_EQ(insn.length(), 1);
}

TEST(DecodedInsn, CpuId) {
  DecodedInsn insn("\x0f\xa2");
  ASSERT_TRUE(insn.is_valid());
  EXPECT_EQ(absl::StripAsciiWhitespace(insn.DebugString()), "cpuid");
  EXPECT_FALSE(insn.is_deterministic());
  EXPECT_EQ(insn.length(), 2);
}

TEST(DecodedInsn, Invalid) {
  DecodedInsn insn("\xf0\x0f");
  ASSERT_FALSE(insn.is_valid());
}

}  // namespace

}  // namespace silifuzz
