// Copyright 2023 The SiliFuzz Authors.
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

#include "./instruction/xed_disassembler.h"

#include <stdint.h>

#include <cstddef>
#include <string>

#include "absl/strings/ascii.h"
#include "./instruction/disassembler.h"
#include "./instruction/xed_util.h"
#include "./util/checks.h"

extern "C" {
#include "third_party/libxed/xed-category-enum.h"
#include "third_party/libxed/xed-decoded-inst-api.h"
#include "third_party/libxed/xed-iclass-enum.h"
}

namespace silifuzz {

XedDisassembler::XedDisassembler() : valid_(false) { InitXedIfNeeded(); }

XedDisassembler::~XedDisassembler() {}

bool XedDisassembler::Disassemble(uint64_t address, const uint8_t* buffer,
                                  size_t buffer_size) {
  address_ = address;

  xed_decoded_inst_zero(&xedd_);
  xed_decoded_inst_set_mode(&xedd_, XED_MACHINE_MODE_LONG_64,
                            XED_ADDRESS_WIDTH_64b);
  valid_ = xed_decode(&xedd_, buffer, buffer_size) == XED_ERROR_NONE;
  return valid_;
}

size_t XedDisassembler::InstructionSize() const {
  return valid_ ? xed_decoded_inst_get_length(&xedd_) : 0;
}

bool XedDisassembler::CanBranch() const {
  if (!valid_) return false;
  return InstructionIsBranch(xed_decoded_inst_inst(&xedd_));
}

bool XedDisassembler::CanLoad() const {
  if (!valid_) return false;

  // Note: XED makes implicit memory operands for call/push/pop/etc explicit
  // through this API.
  const unsigned int num_mem =
      xed_decoded_inst_number_of_memory_operands(&xedd_);
  for (int i = 0; i < num_mem; ++i) {
    if (xed_decoded_inst_mem_read(&xedd_, i)) {
      return true;
    }
  }
  return false;
}

bool XedDisassembler::CanStore() const {
  if (!valid_) return false;

  // Note: XED makes implicit memory operands for call/push/pop/etc explicit
  // through this API.
  const unsigned int num_mem =
      xed_decoded_inst_number_of_memory_operands(&xedd_);
  for (int i = 0; i < num_mem; ++i) {
    if (xed_decoded_inst_mem_written(&xedd_, i)) {
      return true;
    }
  }
  return false;
}

std::string XedDisassembler::FullText() {
  if (valid_) {
    CHECK(FormatInstruction(xedd_, address_, full_text_, sizeof(full_text_)));
    return full_text_;
  } else {
    return kInvalidInstructionName;
  }
}

uint32_t XedDisassembler::InstructionID() const {
  return valid_ ? xed_decoded_inst_get_iclass(&xedd_) : InvalidInstructionID();
}

uint32_t XedDisassembler::InvalidInstructionID() const {
  return XED_ICLASS_INVALID;
}

uint32_t XedDisassembler::NumInstructionIDs() const { return XED_ICLASS_LAST; }

std::string XedDisassembler::InstructionIDName(uint32_t id) const {
  if (id == InvalidInstructionID()) {
    return kInvalidInstructionName;
  }
  std::string name = xed_iclass_enum_t2str(static_cast<xed_iclass_enum_t>(id));
  absl::AsciiStrToLower(&name);
  return name;
}

}  // namespace silifuzz
