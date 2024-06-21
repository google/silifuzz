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

#include "./fuzzer/hashtest/candidate.h"

#include <algorithm>
#include <cstddef>

#include "./fuzzer/hashtest/debugging.h"
#include "./fuzzer/hashtest/register_info.h"
#include "./fuzzer/hashtest/xed_operand_util.h"
#include "./util/checks.h"

extern "C" {
#include "third_party/libxed/xed-interface.h"
}

namespace silifuzz {

namespace {

// Some instructions have fixed registers for inputs and outputs. Since these
// registers cannot be changed, we need to treat them differently than the
// freely assignable registers. For example, we need to ensure that fixed
// registers are not allocated for any other purpose, such as a temporary
// register for one of the instruction's other outputs. We also need to make
// sure fixed inputs are initialized, and that the data from fixed outputs is
// collected.
// This function indentifies the fixed registers that are read and written by
// the `instruction`.
RegisterReadWrite GetFixedRegisterInfo(const xed_inst_t* instruction) {
  RegisterReadWrite info{};

  for (size_t operand_index = 0;
       operand_index < xed_inst_noperands(instruction); ++operand_index) {
    const xed_operand_t* const operand =
        xed_inst_operand(instruction, operand_index);
    if (OperandIsImplicit(operand) || OperandIsSuppressed(operand)) {
      if (OperandIsImmediate(operand)) {
        // Ignore
      } else if (OperandIsRegister(operand)) {
        bool read =
            xed_operand_read(operand) || xed_operand_conditional_write(operand);
        bool written = xed_operand_written(operand);
        if (OperandIsFlagRegister(operand)) {
          if (read) {
            info.read.flags = true;
          }
          if (written) {
            info.written.flags = true;
          }
        } else if (xed_operand_type(operand) == XED_OPERAND_TYPE_REG &&
                   xed_operand_width(operand) == XED_OPERAND_WIDTH_PSEUDO) {
          switch (xed_operand_reg(operand)) {
            case XED_REG_STACKPOP:
            case XED_REG_STACKPUSH:
            case XED_REG_X87POP:
            case XED_REG_X87STATUS:
              // Ignore for now.
              break;
            default:
              DieBecauseOperand(instruction, operand);
          }
        } else if (xed_operand_type(operand) == XED_OPERAND_TYPE_REG) {
          xed_reg_enum_t reg = xed_operand_reg(operand);
          RegisterID reg_id = XedRegToRegisterID(reg);
          if (read) {
            info.read.Set(reg_id, true);
          }
          if (written) {
            info.written.Set(reg_id, true);
          }
        } else if (xed_operand_type(operand) == XED_OPERAND_TYPE_NT_LOOKUP_FN) {
          xed_nonterminal_enum_t name = xed_operand_nonterminal_name(operand);
          RegisterID reg_id = XedNonterminalToRegisterID(name);
          if (read) {
            info.read.Set(reg_id, true);
          }
          if (written) {
            info.written.Set(reg_id, true);
          }
        } else {
          DieBecauseOperand(instruction, operand);
        }
      } else {
        DieBecauseOperand(instruction, operand);
      }
    }
  }
  return info;
}

}  // namespace

RegisterBank InstructionCandidate::OutputMode() const {
  if (reg_written.gp) {
    CHECK(!reg_written.vec && !reg_written.mask && !reg_written.mmx);
    return RegisterBank::kGP;
  } else if (reg_written.vec) {
    CHECK(!reg_written.gp && !reg_written.mask && !reg_written.mmx);
    return RegisterBank::kVec;
  } else if (reg_written.mask) {
    CHECK(!reg_written.gp && !reg_written.vec && !reg_written.mmx);
    return RegisterBank::kMask;
  } else if (reg_written.mmx) {
    CHECK(!reg_written.gp && !reg_written.vec && !reg_written.mask);
    return RegisterBank::kMMX;
  } else {
    // TODO(ncbray): better handling of flag-setting instructions.
    return RegisterBank::kGP;
  }
}

bool IsCandidate(const xed_inst_t* instruction,
                 InstructionCandidate& candidate) {
  candidate = {.instruction = instruction,
               .fixed_reg = GetFixedRegisterInfo(instruction)};

  // Count the implicit inputs and outputs.
  // Generally instruction encodings with implicit operands are a specialized
  // encoding of a more generalized operand but where one of the registers must
  // be set to a specific register, or a constant must be set to one. In these
  // cases the instruction can be encoded more compactly.
  // Typically encodings with implicit operands do not offer distinct
  // functionality, although there are cases such as ROR where the only
  // way to rotate by a variable amount is to use the implicit CL
  // register.
  // The fixed registers should all be implicit or suppressed (otherwise they
  // could be changed), so count them here and then count the explicit registers
  // below.
  candidate.reg_read = candidate.fixed_reg.read.Count();
  candidate.reg_written = candidate.fixed_reg.written.Count();

  for (size_t operand_index = 0;
       operand_index < xed_inst_noperands(instruction); ++operand_index) {
    const xed_operand_t* const operand =
        xed_inst_operand(instruction, operand_index);

    switch (xed_operand_name(operand)) {
      case XED_OPERAND_IMM0:
      case XED_OPERAND_IMM1:
        // Immediates OK.
        CHECK(OperandIsExplicit(operand) || OperandIsImplicit(operand));
        break;
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
        // Registers OK.
        {
          if (OperandIsAddressGPRegister(operand)) {
            // A memory operation, we don't support this yet.
            return false;
          }
          if (OperandIsSuppressed(operand)) {
            if (OperandIsFlagRegister(operand)) {
              continue;
            } else if (xed_operand_type(operand) == XED_OPERAND_TYPE_REG &&
                       (xed_operand_reg(operand) == XED_REG_STACKPOP ||
                        xed_operand_reg(operand) == XED_REG_STACKPUSH)) {
              // No memory operations.
              return false;
            }
          }
          bool read = xed_operand_read(operand) ||
                      xed_operand_conditional_write(operand);
          bool written = xed_operand_written(operand);

          if (OperandIsExplicit(operand)) {
            if (OperandIsGPRegister(operand)) {
              if (read) {
                candidate.reg_read.gp++;
              }
              if (written) {
                candidate.reg_written.gp++;
              }
            } else if (OperandIsVectorRegister(operand)) {
              candidate.vector_width =
                  std::max(candidate.vector_width, VectorWidth(operand));
              if (read) {
                candidate.reg_read.vec++;
              }
              if (written) {
                candidate.reg_written.vec++;
              }
            } else if (OperandIsMaskRegister(operand)) {
              if (read) {
                candidate.reg_read.mask++;
              }
              if (written) {
                candidate.reg_written.mask++;
              }
            } else if (OperandIsMMXRegister(operand)) {
              if (read) {
                candidate.reg_read.mmx++;
              }
              if (written) {
                candidate.reg_written.mmx++;
              }
            } else {
              DieBecauseOperand(instruction, operand);
            }
          }

          xed_operand_width_enum_t w = xed_operand_width(operand);
          switch (w) {
            case XED_OPERAND_WIDTH_V:
              candidate.width_16 = true;
              candidate.width_32 = true;
              candidate.width_64 = true;
              break;
            case XED_OPERAND_WIDTH_Z:
              candidate.width_16 = true;
              candidate.width_32 = true;
              break;
            case XED_OPERAND_WIDTH_Y:
              candidate.width_32 = true;
              candidate.width_64 = true;
              break;
            case XED_OPERAND_WIDTH_MSKW:
              if (OperandIsWritemask(operand)) {
                candidate.writemask = true;
              }
              break;
            default:
              break;
          }
        }
        break;
      default:
        // Make sure none of the other operands are being used.
        DieBecauseOperand(instruction, operand);
    }
  }

  return true;
}

}  // namespace silifuzz
