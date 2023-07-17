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

#include "./tracing/xed_disassembler.h"

#include <stdint.h>

#include <cstddef>
#include <limits>
#include <string>

#include "absl/base/call_once.h"
#include "absl/strings/ascii.h"
#include "absl/strings/str_cat.h"
#include "./util/checks.h"

namespace silifuzz {

namespace {
absl::once_flag xed_init_once;
}

XedDisassembler::XedDisassembler() : valid_(false) {
  // It should be safe to call xed_tables_init multiple times from a single
  // thread (the implementation checks if it's been called before) but it
  // doesn't look safe if it's being called by multiple threads at the same
  // time.
  absl::call_once(xed_init_once, xed_tables_init);
}

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

std::string XedDisassembler::FullText() {
  if (valid_) {
    xed_print_info_t pi;
    xed_init_print_info(&pi);
    pi.p = &xedd_;
    pi.buf = full_text_;
    pi.blen = sizeof(full_text_) - 1;
    pi.context = nullptr;
    pi.disassembly_callback = nullptr;
    pi.runtime_address = address_;
    pi.syntax = XED_SYNTAX_INTEL;
    pi.format_options_valid = false;
    pi.buf[0] = 0;
    CHECK(xed_format_generic(&pi));
    return full_text_;
  } else {
    return "unknown";
  }
}

uint32_t XedDisassembler::InstructionID() const {
  return valid_ ? xed_decoded_inst_get_iclass(&xedd_) : InvalidInstructionID();
}

uint32_t XedDisassembler::InvalidInstructionID() const {
  return std::numeric_limits<uint32_t>::max();
}

uint32_t XedDisassembler::NumInstructionIDs() const { return XED_ICLASS_LAST; }

std::string XedDisassembler::InstructionIDName(uint32_t id) const {
  std::string name = xed_iclass_enum_t2str(static_cast<xed_iclass_enum_t>(id));
  absl::AsciiStrToLower(&name);
  return name;
}

}  // namespace silifuzz
