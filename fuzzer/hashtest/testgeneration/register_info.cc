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

#include "./fuzzer/hashtest/testgeneration/register_info.h"

#include <bitset>
#include <cstddef>

#include "./util/checks.h"

extern "C" {
#include "third_party/libxed/xed-interface.h"
}

namespace silifuzz {

namespace {

constexpr struct {
  RegisterBank bank;
  unsigned int width;
  xed_reg_enum_t first;
  xed_reg_enum_t last;
} kRegRanges[] = {
    {
        .bank = RegisterBank::kGP,
        .width = 8,
        .first = XED_REG_GPR8_FIRST,
        .last = XED_REG_GPR8_LAST,
    },
    {
        .bank = RegisterBank::kGP,
        .width = 8,
        .first = XED_REG_GPR8h_FIRST,
        .last = XED_REG_GPR8h_LAST,
    },
    {
        .bank = RegisterBank::kGP,
        .width = 16,
        .first = XED_REG_GPR16_FIRST,
        .last = XED_REG_GPR16_LAST,
    },
    {
        .bank = RegisterBank::kGP,
        .width = 32,
        .first = XED_REG_GPR32_FIRST,
        .last = XED_REG_GPR32_LAST,
    },
    {
        .bank = RegisterBank::kGP,
        .width = 64,
        .first = XED_REG_GPR64_FIRST,
        .last = XED_REG_GPR64_LAST,
    },
    {
        .bank = RegisterBank::kVec,
        .width = 128,
        .first = XED_REG_XMM_FIRST,
        .last = XED_REG_XMM_LAST,
    },
    {
        .bank = RegisterBank::kVec,
        .width = 256,
        .first = XED_REG_YMM_FIRST,
        .last = XED_REG_YMM_LAST,
    },
    {
        .bank = RegisterBank::kVec,
        .width = 512,
        .first = XED_REG_ZMM_FIRST,
        .last = XED_REG_ZMM_LAST,
    },
    {
        // HACK: treat X87 as MMX.
        .bank = RegisterBank::kMMX,
        .width = 64,
        .first = XED_REG_X87_FIRST,
        .last = XED_REG_X87_LAST,
    },
};

template <size_t N>
void SetBit(std::bitset<N>& bitset, unsigned int index, bool value,
            bool value_must_change) {
  if (value_must_change) {
    CHECK_NE(bitset.test(index), value);
  }
  bitset.set(index, value);
}

}  // namespace

// Note: relies on all the enum orderings being consistent, including for GPR8h
// which only covers the start of GRP8.
RegisterID XedRegToRegisterID(xed_reg_enum_t reg) {
  for (const auto& range : kRegRanges) {
    if (reg >= range.first && reg <= range.last) {
      return RegisterID{.bank = range.bank,
                        .index = static_cast<unsigned int>(reg - range.first)};
    }
  }
  LOG_FATAL("Unimplemented register: ", xed_reg_enum_t2str(reg));
}

RegisterID XedNonterminalToRegisterID(xed_nonterminal_enum_t name) {
  if (name == XED_NONTERMINAL_ORAX) {
    return XedRegToRegisterID(XED_REG_RAX);
  } else if (name == XED_NONTERMINAL_ORDX) {
    return XedRegToRegisterID(XED_REG_RDX);
  }
  LOG_FATAL("Unimplemented nonterminal: ", xed_nonterminal_enum_t2str(name));
}

xed_reg_enum_t RegisterIDToXedReg(RegisterID id, unsigned int width) {
  for (const auto& range : kRegRanges) {
    if (id.bank == range.bank && width == range.width) {
      CHECK_LE(id.index, range.last - range.first);
      return static_cast<xed_reg_enum_t>(range.first + id.index);
    }
  }
  LOG_FATAL("Unimplemented register: ", (int)id.bank, "/", id.index, "/",
            width);
}

size_t RegisterCount::Get(RegisterBank bank) const {
  switch (bank) {
    case RegisterBank::kGP:
      return gp;
    case RegisterBank::kVec:
      return vec;
    case RegisterBank::kMask:
      return mask;
    case RegisterBank::kMMX:
      return mmx;
    default:
      LOG_FATAL("Unimplemented bank: ", (int)bank);
      break;
  }
}

bool RegisterMask::Get(RegisterID id) const {
  switch (id.bank) {
    case RegisterBank::kGP:
      return gp.test(id.index);
    case RegisterBank::kVec:
      return vec.test(id.index);
    case RegisterBank::kMask:
      return mask.test(id.index);
    case RegisterBank::kMMX:
      return mmx.test(id.index);
    default:
      LOG_FATAL("Unimplemented bank: ", (int)id.bank);
      break;
  }
}

void RegisterMask::Set(RegisterID id, bool value, bool value_must_change) {
  switch (id.bank) {
    case RegisterBank::kGP:
      SetBit(gp, id.index, value, value_must_change);
      break;
    case RegisterBank::kVec:
      SetBit(vec, id.index, value, value_must_change);
      break;
    case RegisterBank::kMask:
      SetBit(mask, id.index, value, value_must_change);
      break;
    case RegisterBank::kMMX:
      SetBit(mmx, id.index, value, value_must_change);
      break;
    default:
      LOG_FATAL("Unimplemented bank: ", (int)id.bank);
      break;
  }
}

RegisterCount RegisterMask::Count() const {
  return {.gp = gp.count(),
          .vec = vec.count(),
          .mask = mask.count(),
          .mmx = mmx.count()};
}

}  // namespace silifuzz
