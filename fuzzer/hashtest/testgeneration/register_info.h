// Copyright 2024 The Silifuzz Authors.
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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_TESTGENERATION_REGISTER_INFO_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_TESTGENERATION_REGISTER_INFO_H_

#include <bitset>
#include <cstddef>

extern "C" {
#include "third_party/libxed/xed-interface.h"
}

namespace silifuzz {

// The name of a bank of registers.
// A "bank" must contain more than one register. For example, "flags" is not a
// bank.
enum class RegisterBank {
  kGP,
  kVec,
  kMask,
  kMMX,
};

// A width-less name for a register.
// For example the "A", which may be referred to as RAX, EAX, AX, or AL.
struct RegisterID {
  RegisterBank bank;
  unsigned int index;

  bool operator==(const RegisterID&) const = default;
};

// A count of the number of registers in each bank.
struct RegisterCount {
  size_t gp = 0;
  size_t vec = 0;
  size_t mask = 0;
  size_t mmx = 0;

  size_t Get(RegisterBank bank) const;
  size_t Total() const { return gp + vec + mask + mmx; }
};

// A bitmask of the x86_64 registers that we want to reason about.
struct RegisterMask {
  std::bitset<16> gp;
  std::bitset<32> vec;
  std::bitset<8> mask;
  std::bitset<8> mmx;
  bool flags;

  bool Get(RegisterID id) const;

  void Set(RegisterID id, bool value, bool value_must_change = false);

  // CHECK the bit was set and then clear it.
  void Clear(RegisterID id) { Set(id, false, true); }

  RegisterCount Count() const;
};

// Map from a XED register to the internal name.
RegisterID XedRegToRegisterID(xed_reg_enum_t reg);

// Typically XED instruction operands refers to specific registers, and this is
// covered by XedRegToRegisterID.  However, in some cases XED operands refer to
// "nonterminals" such as XED_NONTERMINAL_ORAX (which would refer to any width
// of the "A" register).
RegisterID XedNonterminalToRegisterID(xed_nonterminal_enum_t name);

// Map from a RegisterID to a XED register, given a specific width.
// Note: does not support mask registers because the register name does not
// imply a width.
xed_reg_enum_t RegisterIDToXedReg(RegisterID id, unsigned int width);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_TESTGENERATION_REGISTER_INFO_H_
