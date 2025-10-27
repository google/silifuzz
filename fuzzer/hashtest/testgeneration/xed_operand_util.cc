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

#include "./fuzzer/hashtest/testgeneration/xed_operand_util.h"

#include <algorithm>
#include <cstddef>

#include "./util/checks.h"

extern "C" {
#include "third_party/libxed/xed-interface.h"
}

namespace silifuzz {

bool OperandIsExplicit(const xed_operand_t* operand) {
  return xed_operand_operand_visibility(operand) == XED_OPVIS_EXPLICIT;
}

bool OperandIsImplicit(const xed_operand_t* operand) {
  return xed_operand_operand_visibility(operand) == XED_OPVIS_IMPLICIT;
}

bool OperandIsSuppressed(const xed_operand_t* operand) {
  return xed_operand_operand_visibility(operand) == XED_OPVIS_SUPPRESSED;
}

bool OperandIsFlagRegister(const xed_operand_t* operand) {
  return xed_operand_nonterminal_name(operand) == XED_NONTERMINAL_RFLAGS;
}

bool OperandIsSegmentRegister(const xed_operand_t* operand) {
  xed_nonterminal_enum_t name = xed_operand_nonterminal_name(operand);
  return name == XED_NONTERMINAL_SEG || name == XED_NONTERMINAL_SEG_MOV;
}

bool OperandIsMMXRegister(const xed_operand_t* operand) {
  xed_nonterminal_enum_t name = xed_operand_nonterminal_name(operand);
  return name == XED_NONTERMINAL_MMX_B || name == XED_NONTERMINAL_MMX_R;
}

bool OperandIsXMMRegister(const xed_operand_t* operand) {
  xed_nonterminal_enum_t name = xed_operand_nonterminal_name(operand);

  switch (name) {
    case XED_NONTERMINAL_XMM_B:
    case XED_NONTERMINAL_XMM_B3:
    case XED_NONTERMINAL_XMM_B3_32:
    case XED_NONTERMINAL_XMM_B3_64:
    case XED_NONTERMINAL_XMM_B_32:
    case XED_NONTERMINAL_XMM_B_64:
    case XED_NONTERMINAL_XMM_N:
    case XED_NONTERMINAL_XMM_N3:
    case XED_NONTERMINAL_XMM_N3_32:
    case XED_NONTERMINAL_XMM_N3_64:
    case XED_NONTERMINAL_XMM_N_32:
    case XED_NONTERMINAL_XMM_N_64:
    case XED_NONTERMINAL_XMM_R:
    case XED_NONTERMINAL_XMM_R3:
    case XED_NONTERMINAL_XMM_R3_32:
    case XED_NONTERMINAL_XMM_R3_64:
    case XED_NONTERMINAL_XMM_R_32:
    case XED_NONTERMINAL_XMM_R_64:
    case XED_NONTERMINAL_XMM_SE:
    case XED_NONTERMINAL_XMM_SE32:
    case XED_NONTERMINAL_XMM_SE64:
      return true;
    default:
      return false;
  }
}

bool OperandIsYMMRegister(const xed_operand_t* operand) {
  xed_nonterminal_enum_t name = xed_operand_nonterminal_name(operand);

  switch (name) {
    case XED_NONTERMINAL_YMM_B:
    case XED_NONTERMINAL_YMM_B3:
    case XED_NONTERMINAL_YMM_B3_32:
    case XED_NONTERMINAL_YMM_B3_64:
    case XED_NONTERMINAL_YMM_B_32:
    case XED_NONTERMINAL_YMM_B_64:
    case XED_NONTERMINAL_YMM_N:
    case XED_NONTERMINAL_YMM_N3:
    case XED_NONTERMINAL_YMM_N3_32:
    case XED_NONTERMINAL_YMM_N3_64:
    case XED_NONTERMINAL_YMM_N_32:
    case XED_NONTERMINAL_YMM_N_64:
    case XED_NONTERMINAL_YMM_R:
    case XED_NONTERMINAL_YMM_R3:
    case XED_NONTERMINAL_YMM_R3_32:
    case XED_NONTERMINAL_YMM_R3_64:
    case XED_NONTERMINAL_YMM_R_32:
    case XED_NONTERMINAL_YMM_R_64:
    case XED_NONTERMINAL_YMM_SE:
    case XED_NONTERMINAL_YMM_SE32:
      return true;
    default:
      return false;
  }
}

bool OperandIsZMMRegister(const xed_operand_t* operand) {
  xed_nonterminal_enum_t name = xed_operand_nonterminal_name(operand);

  switch (name) {
    case XED_NONTERMINAL_ZMM_B3:
    case XED_NONTERMINAL_ZMM_B3_32:
    case XED_NONTERMINAL_ZMM_B3_64:
    case XED_NONTERMINAL_ZMM_N3:
    case XED_NONTERMINAL_ZMM_N3_32:
    case XED_NONTERMINAL_ZMM_N3_64:
    case XED_NONTERMINAL_ZMM_R3:
    case XED_NONTERMINAL_ZMM_R3_32:
    case XED_NONTERMINAL_ZMM_R3_64:
      return true;
    default:
      return false;
  }
}

bool OperandIsVectorRegister(const xed_operand_t* operand) {
  return OperandIsXMMRegister(operand) || OperandIsYMMRegister(operand) ||
         OperandIsZMMRegister(operand);
}

size_t VectorWidth(const xed_operand_t* operand) {
  if (OperandIsXMMRegister(operand)) {
    return 128U;
  } else if (OperandIsYMMRegister(operand)) {
    return 256U;
  } else if (OperandIsZMMRegister(operand)) {
    return 512U;
  } else {
    LOG_FATAL(
        "Unsupported operand: ",
        xed_nonterminal_enum_t2str(xed_operand_nonterminal_name(operand)));
  }
}

bool OperandIsMaskRegister(const xed_operand_t* operand) {
  xed_nonterminal_enum_t name = xed_operand_nonterminal_name(operand);

  switch (name) {
    case XED_NONTERMINAL_MASK1:
    case XED_NONTERMINAL_MASKNOT0:
    case XED_NONTERMINAL_MASK_B:
    case XED_NONTERMINAL_MASK_N:
    case XED_NONTERMINAL_MASK_N32:
    case XED_NONTERMINAL_MASK_N64:
    case XED_NONTERMINAL_MASK_R:
      return true;
    default:
      return false;
  }
}

bool OperandIsWritemask(const xed_operand_t* operand) {
  return xed_operand_nonterminal_name(operand) == XED_NONTERMINAL_MASK1;
}

bool OperandIsGPRegister(const xed_operand_t* operand) {
  xed_nonterminal_enum_t name = xed_operand_nonterminal_name(operand);
  switch (name) {
    case XED_NONTERMINAL_GPR16_B:
    case XED_NONTERMINAL_GPR16_N:
    case XED_NONTERMINAL_GPR16_R:
    case XED_NONTERMINAL_GPR16_SB:
    case XED_NONTERMINAL_GPR32_B:
    case XED_NONTERMINAL_GPR32_N:
    case XED_NONTERMINAL_GPR32_R:
    case XED_NONTERMINAL_GPR32_SB:
    case XED_NONTERMINAL_GPR64_B:
    case XED_NONTERMINAL_GPR64_B_NORSP:
    case XED_NONTERMINAL_GPR64_N:
    case XED_NONTERMINAL_GPR64_N_NORSP:
    case XED_NONTERMINAL_GPR64_R:
    case XED_NONTERMINAL_GPR64_SB:
    case XED_NONTERMINAL_GPR8_B:
    case XED_NONTERMINAL_GPR8_N:
    case XED_NONTERMINAL_GPR8_R:
    case XED_NONTERMINAL_GPR8_SB:
    case XED_NONTERMINAL_GPRV_B:
    case XED_NONTERMINAL_GPRV_N:
    case XED_NONTERMINAL_GPRV_R:
    case XED_NONTERMINAL_GPRV_SB:
    case XED_NONTERMINAL_GPRY_B:
    case XED_NONTERMINAL_GPRY_R:
    case XED_NONTERMINAL_GPRZ_B:
    case XED_NONTERMINAL_GPRZ_R:
    case XED_NONTERMINAL_VGPR32_B:
    case XED_NONTERMINAL_VGPR32_B_32:
    case XED_NONTERMINAL_VGPR32_B_64:
    case XED_NONTERMINAL_VGPR32_N:
    case XED_NONTERMINAL_VGPR32_N_32:
    case XED_NONTERMINAL_VGPR32_N_64:
    case XED_NONTERMINAL_VGPR32_R:
    case XED_NONTERMINAL_VGPR32_R_32:
    case XED_NONTERMINAL_VGPR32_R_64:
    case XED_NONTERMINAL_VGPR64_B:
    case XED_NONTERMINAL_VGPR64_N:
    case XED_NONTERMINAL_VGPR64_R:
    case XED_NONTERMINAL_VGPRY_B:
    case XED_NONTERMINAL_VGPRY_N:
    case XED_NONTERMINAL_VGPRY_R:
      return true;
    default:
      return false;
  }
}

bool OperandIsAddressGPRegister(const xed_operand_t* operand) {
  xed_nonterminal_enum_t name = xed_operand_nonterminal_name(operand);
  switch (name) {
    case XED_NONTERMINAL_A_GPR_B:
    case XED_NONTERMINAL_A_GPR_R:
      return true;
    default:
      return false;
  }
}

bool OperandIsTile(const xed_operand_t* operand) {
  xed_nonterminal_enum_t name = xed_operand_nonterminal_name(operand);
  switch (name) {
    case XED_NONTERMINAL_TMM_B:
    case XED_NONTERMINAL_TMM_N:
    case XED_NONTERMINAL_TMM_R:
    case XED_NONTERMINAL_TMM_R3:
      return true;
    default:
      return false;
  }
}

bool OperandIsRegister(const xed_operand_t* operand) {
  switch (xed_operand_name(operand)) {
    case XED_OPERAND_REG0:
    case XED_OPERAND_REG1:
    case XED_OPERAND_REG2:
    case XED_OPERAND_REG3:
    case XED_OPERAND_REG4:
    case XED_OPERAND_REG5:
    case XED_OPERAND_REG6:
    case XED_OPERAND_REG7:
    case XED_OPERAND_REG8:
    case XED_OPERAND_REG9:
      return true;
    default:
      return false;
  }
}

bool OperandIsImmediate(const xed_operand_t* operand) {
  switch (xed_operand_name(operand)) {
    case XED_OPERAND_IMM0:
    case XED_OPERAND_IMM1:
      return true;
    default:
      return false;
  }
}

bool OperandIsMemory(const xed_operand_t* operand) {
  switch (xed_operand_name(operand)) {
    case XED_OPERAND_MEM0:
    case XED_OPERAND_MEM1:
      return true;
    default:
      return false;
  }
}

size_t OperandBitWidth(const xed_operand_t* operand,
                       unsigned int effective_op_width) {
  switch (xed_operand_width(operand)) {
    case XED_OPERAND_WIDTH_B:
      return 8;
    case XED_OPERAND_WIDTH_W:
      return 16;
    case XED_OPERAND_WIDTH_D:
      return 32;
    case XED_OPERAND_WIDTH_Q:
      return 64;
    case XED_OPERAND_WIDTH_V:
      return effective_op_width;
    case XED_OPERAND_WIDTH_Z:
      // 32-bit ceil
      return std::min(effective_op_width, 32U);
    case XED_OPERAND_WIDTH_Y:
      // 32-bit floor
      return std::max(effective_op_width, 32U);
    default:
      LOG_FATAL("Unsupported operand width: ",
                xed_operand_width_enum_t2str(xed_operand_width(operand)));
  }
}

}  // namespace silifuzz
