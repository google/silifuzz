// Copyright 2025 The SiliFuzz Authors.
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

#include "./fuzzer/hashtest/testgeneration/register_info.h"

#include <cstddef>

#include "gtest/gtest.h"

namespace silifuzz {
namespace {

TEST(RegisterInfo, RegisterTranslation) {
  // HACK to get number of registers in each bank.
  RegisterMask m{};

  // General purpose registers.
  for (unsigned int i = 0; i < m.gp.size(); ++i) {
    RegisterID original{.bank = RegisterBank::kGP, .index = i};
    for (size_t width : {8, 16, 32, 64}) {
      RegisterID roundtrip =
          XedRegToRegisterID(RegisterIDToXedReg(original, width));
      EXPECT_EQ(roundtrip, original);
    }
  }

  // Vector registers.
  for (unsigned int i = 0; i < m.vec.size(); ++i) {
    RegisterID original{.bank = RegisterBank::kVec, .index = i};
    for (size_t width : {128, 256, 512}) {
      RegisterID roundtrip =
          XedRegToRegisterID(RegisterIDToXedReg(original, width));
      EXPECT_EQ(roundtrip, original);
    }
  }

  // MMX registers.
  for (unsigned int i = 0; i < m.mmx.size(); ++i) {
    RegisterID original{.bank = RegisterBank::kMMX, .index = i};
    for (size_t width : {64}) {
      RegisterID roundtrip =
          XedRegToRegisterID(RegisterIDToXedReg(original, width));
      EXPECT_EQ(roundtrip, original);
    }
  }
}

TEST(RegisterInfo, NonterminalTranslation) {
  EXPECT_EQ(
      XED_REG_RAX,
      RegisterIDToXedReg(XedNonterminalToRegisterID(XED_NONTERMINAL_ORAX), 64));

  EXPECT_EQ(
      XED_REG_RDX,
      RegisterIDToXedReg(XedNonterminalToRegisterID(XED_NONTERMINAL_ORDX), 64));
}

TEST(RegisterInfo, CountEmpty) {
  RegisterMask m{};
  EXPECT_EQ(m.Count().Total(), 0);
}

TEST(RegisterInfo, CountFlags) {
  // Flags are not part of a register bank, so they are not counted.
  // This is a little strange, but code elsewhere depends on this behavior so
  // test it to confirm this is the behavior.
  RegisterMask m{};
  m.flags = true;
  EXPECT_EQ(m.Count().Total(), 0);
}

TEST(RegisterInfo, RegisterMask) {
  constexpr RegisterBank kBanks[] = {RegisterBank::kGP, RegisterBank::kVec,
                                     RegisterBank::kMask, RegisterBank::kMMX};
  for (RegisterBank bank1 : kBanks) {
    for (RegisterBank bank2 : kBanks) {
      RegisterMask m{};

      RegisterID id1{.bank = bank1, .index = 0};
      RegisterID id2{.bank = bank2, .index = 1};

      // Set registers.
      m.Set(id1, true);
      m.Set(id2, true);

      // Check registers were set.
      EXPECT_TRUE(m.Get(id1));
      EXPECT_TRUE(m.Get(id2));

      // Count set registers.
      RegisterCount count = m.Count();
      EXPECT_EQ(count.Total(), 2);
      size_t expected_count = bank1 == bank2 ? 2 : 1;
      EXPECT_EQ(count.Get(bank1), expected_count);
      EXPECT_EQ(count.Get(bank2), expected_count);

      // Unset the registers.
      m.Clear(id1);
      m.Clear(id2);

      // Check registers were unset.
      EXPECT_FALSE(m.Get(id1));
      EXPECT_FALSE(m.Get(id2));

      // Count to make sure everything is empty.
      count = m.Count();
      EXPECT_EQ(count.Total(), 0);
      EXPECT_EQ(count.Get(bank1), 0);
      EXPECT_EQ(count.Get(bank2), 0);
    }
  }
}

}  // namespace
}  // namespace silifuzz
