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

#include "./fuzzer/hashtest/testgeneration/debugging.h"

#include <cstddef>
#include <iostream>

#include "./util/checks.h"

extern "C" {
#include "third_party/libxed/xed-interface.h"
}

namespace silifuzz {

void DumpInstruction(const xed_inst_t* instruction) {
  std::cout << "\n";
  std::cout << "==========================================================\n";
  std::cout << xed_iclass_enum_t2str(xed_inst_iclass(instruction)) << " / "
            << xed_iform_enum_t2str(xed_inst_iform_enum(instruction)) << " / "
            << xed_category_enum_t2str(xed_inst_category(instruction)) << " / "
            << xed_extension_enum_t2str(xed_inst_extension(instruction))
            << " / " << xed_isa_set_enum_t2str(xed_inst_isa_set(instruction))
            << "\n";
  for (size_t a = 0; a < xed_attribute_max(); ++a) {
    xed_attribute_enum_t attr = xed_attribute(a);
    if (xed_inst_get_attribute(instruction, attr)) {
      std::cout << "    + " << xed_attribute_enum_t2str(attr) << "\n";
    }
  }

  for (size_t operand_index = 0;
       operand_index < xed_inst_noperands(instruction); ++operand_index) {
    const xed_operand_t* const operand =
        xed_inst_operand(instruction, operand_index);
    std::cout << xed_operand_enum_t2str(
                     static_cast<xed_operand_enum_t>(operand->_name))
              << "\n";
  }
  std::cout << "\n";
}

void DieBecauseOperand(const xed_inst_t* instruction,
                       const xed_operand_t* operand) {
  DumpInstruction(instruction);

  LOG_FATAL(
      xed_iclass_enum_t2str(xed_inst_iclass(instruction)), " / ",
      xed_operand_enum_t2str(static_cast<xed_operand_enum_t>(operand->_name)));
}

}  // namespace silifuzz
