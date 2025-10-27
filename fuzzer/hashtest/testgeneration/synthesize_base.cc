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

#include "./fuzzer/hashtest/testgeneration/synthesize_base.h"

#include <cstddef>
#include <cstdint>

#include "./fuzzer/hashtest/testgeneration/register_info.h"
#include "./instruction/xed_util.h"
#include "./util/checks.h"

extern "C" {
#include "third_party/libxed/xed-interface.h"
}

namespace silifuzz {

// Mark which registers are: 1) temporary values, 2) entropy values, and 3)
// should not be used when generating tests.
void InitRegisterLayout(xed_chip_enum_t chip, RegisterPool& rpool) {
  rpool.vec_width = ChipVectorRegisterWidth(chip);
  rpool.mask_width = ChipMaskRegisterWidth(chip);

  // GP registers.
  const unsigned int stack_index = XedRegToRegisterID(XED_REG_RSP).index;
  for (int i = 0; i < rpool.tmp.gp.size(); ++i) {
    if (i == kLoopIndex) {
      // Iteration reg.
    } else if (i == stack_index) {
      // Stack pointer.
    } else if (i >= 9 && i < 16) {
      // Use higher registers for entropy since the lower registers may be fixed
      // read/write targets for some instructions.
      rpool.entropy.gp[i] = true;
    } else {
      rpool.tmp.gp[i] = true;
    }
  }

  // Vector registers.
  // TODO(ncbray): when is this 16 registers vs. 32?
  if (rpool.vec_width > 0) {
    for (int i = 0; i < rpool.tmp.vec.size(); ++i) {
      // Entropy needs to be initializable by Silifuzz.
      if (i >= 8 && i < 16) {
        // Use higher registers for entropy since the XMM0 may be a fixed
        // read/write target for some instructions.
        rpool.entropy.vec[i] = true;
      } else if (i >= 16) {
        // Extended registers.
      } else {
        rpool.tmp.vec[i] = true;
      }
    }
  }

  // Mask registers.
  if (rpool.mask_width > 0) {
    for (int i = 0; i < rpool.tmp.mask.size(); ++i) {
      if (i >= 4 && i < 8) {
        // k0 cannot be an entropy register because it has a special meaning
        // when used as a write mask.
        rpool.entropy.mask[i] = true;
      } else {
        rpool.tmp.mask[i] = true;
      }
    }
  }

  // MMX registers.
  for (int i = 0; i < rpool.tmp.mmx.size(); ++i) {
    if (i >= 4 && i < 8) {
      rpool.entropy.mmx[i] = true;
    } else {
      rpool.tmp.mmx[i] = true;
    }
  }
}

void Emit(InstructionBuilder& builder, InstructionBlock& block) {
  uint8_t ibuf[16];
  size_t actual_len = sizeof(ibuf);
  CHECK(builder.Encode(ibuf, actual_len))
      << xed_iclass_enum_t2str(builder.iclass());
  block.EmitInstruction(ibuf, actual_len);
}

// TODO(ncbray): support "high byte" iforms. Unfortunately these can only target
// AH, BH, CH, and DH so this looks very similar to supporting fixed registers.
xed_encoder_operand_t GPRegOperand(unsigned int index, size_t width) {
  return xed_reg(RegisterIDToXedReg(
      RegisterID{.bank = RegisterBank::kGP, .index = index}, width));
}

xed_encoder_operand_t VecRegOperand(unsigned int index, size_t width) {
  return xed_reg(RegisterIDToXedReg(
      RegisterID{.bank = RegisterBank::kVec, .index = index}, width));
}

xed_encoder_operand_t MaskRegOperand(unsigned int index) {
  CHECK_LT(index, 8);
  return xed_reg(static_cast<xed_reg_enum_t>(XED_REG_MASK_FIRST + index));
}

xed_encoder_operand_t MMXRegOperand(unsigned int index) {
  CHECK_LT(index, 8);
  return xed_reg(static_cast<xed_reg_enum_t>(XED_REG_MMX_FIRST + index));
}

}  // namespace silifuzz
