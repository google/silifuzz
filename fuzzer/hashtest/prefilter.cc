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

#include "./fuzzer/hashtest/prefilter.h"

#include <cstddef>

#include "./fuzzer/hashtest/xed_operand_util.h"
#include "./instruction/xed_util.h"

extern "C" {
#include "third_party/libxed/xed-interface.h"
}

namespace silifuzz {

namespace {

// Filter out all the operands we don't support, yet.
bool PrefilterOperands(const xed_inst_t* instruction) {
  for (size_t operand_index = 0;
       operand_index < xed_inst_noperands(instruction); ++operand_index) {
    const xed_operand_t* const operand =
        xed_inst_operand(instruction, operand_index);
    switch (xed_operand_name(operand)) {
      case XED_OPERAND_MEM0:
      case XED_OPERAND_MEM1:
        // No memory operations.
        return false;
      case XED_OPERAND_RELBR:
      case XED_OPERAND_ABSBR:
        // No branches.
        return false;
      case XED_OPERAND_PTR:
        // Jump far?
        return false;
      case XED_OPERAND_AGEN:
        // We might be able to support LEA-like operations, but ignore them
        // now for simplicity.
        return false;
      default:
        break;
    }

    // An address-sized operand implies this is a strangely-defined instruction
    // that operates on memory, such as VMRUN and CLZERO.
    if (xed_operand_width(operand) == XED_OPERAND_WIDTH_ASZ) {
      return false;
    }

    // Simplify things by not handling segment registers.
    if (OperandIsSegmentRegister(operand)) {
      return false;
    }

    // Figuring out how to manage tile registers will be interesting.
    if (OperandIsTile(operand)) {
      return false;
    }
  }
  return true;
}

}  // namespace

bool PrefilterInstruction(const xed_inst_t* instruction) {
  //
  // Instructions that are generally problematic for userspace tests.
  //

  if (!InstructionIsDeterministicInRunner(instruction)) {
    return false;
  }
  // Filter out privileged instructions.
  if (!InstructionCanRunInUserSpace(instruction)) {
    return false;
  }
  // Also privileged, in practice.
  if (InstructionRequiresIOPrivileges(instruction)) {
    return false;
  }

  const xed_iclass_enum_t iclass = xed_inst_iclass(instruction);
  const xed_category_enum_t category = xed_inst_category(instruction);
  const xed_extension_enum_t extension = xed_inst_extension(instruction);

  // Memory protection extensions, likely disabled, can cause exceptions if
  // enabled.
  if (extension == XED_EXTENSION_MPX) {
    return false;
  }

  // SGX is unlikely to be enabled, and if it was we wouldn't want to deal with
  // these instructions.
  if (category == XED_CATEGORY_SGX) {
    return false;
  }

  // Virtualization support.
  if (category == XED_CATEGORY_VTX || extension == XED_EXTENSION_SVM) {
    return false;
  }

  // Trailing bit manipulation is an AMD extension that does not appear to be
  // supported on modern AMD chips. XED, however, believes it is. It was never
  // supported on Intel chips.
  // Solve this issue by unconditionally filtering out this extension.
  if (extension == XED_EXTENSION_TBM) {
    return false;
  }

  // Restricted transactional memory.
  if (extension == XED_EXTENSION_RTM) {
    return false;
  }

  // Control-flow Enforcement Technology.
  // Includes the shadow stack, which is a bit of state we don't handle.
  if (category == XED_CATEGORY_CET) {
    return false;
  }

  // User interrupts.
  if (category == XED_CATEGORY_UINTR) {
    return false;
  }

  // Safe mode extensions.
  if (extension == XED_EXTENSION_SMX) {
    return false;
  }

  // Should always fault.
  // Note: RSM is "resume from system management mode" and since we are never in
  // that mode it should always fault.
  if (iclass == XED_ICLASS_UD0 || iclass == XED_ICLASS_UD1 ||
      iclass == XED_ICLASS_UD2 || iclass == XED_ICLASS_INT3 ||
      iclass == XED_ICLASS_RSM) {
    return false;
  }

  //
  // Instructions that are problematic for structured tests, specifically.
  //

  // Don't want to reason about control flow.
  if (InstructionIsBranch(instruction)) {
    return false;
  }

  // x87 state management is a bit complicated, ignore it for now.
  if (InstructionIsX87(instruction)) {
    return false;
  }

  // NOPs should not be observable, no point in generating them.
  if (category == XED_CATEGORY_NOP || category == XED_CATEGORY_WIDENOP) {
    return false;
  }
  // Clearing register sets destroys a bunch of entropy.
  if (iclass == XED_ICLASS_EMMS || iclass == XED_ICLASS_VZEROALL ||
      iclass == XED_ICLASS_VZEROUPPER) {
    return false;
  }

  // Divides have a habit of throwing exceptions.
  // It would be nice if we could support these, somehow...
  if (iclass == XED_ICLASS_DIV || iclass == XED_ICLASS_IDIV) {
    return false;
  }

  return PrefilterOperands(instruction);
}
}  // namespace silifuzz
