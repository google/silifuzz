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

#include "./tracing/capstone_disassembler.h"

#include <stdint.h>

#include <cstddef>
#include <limits>
#include <string>

#include "absl/strings/str_cat.h"
#include "third_party/capstone/capstone.h"
#include "./util/checks.h"

namespace silifuzz {

template <typename Arch>
CapstoneDisassembler<Arch>::CapstoneDisassembler() : valid_(false) {
  cs_arch arch;
  cs_mode mode;
  if constexpr (Arch::architecture_id == ArchitectureId::kX86_64) {
    arch = CS_ARCH_X86;
    mode = CS_MODE_64;
    num_instruction_ids_ = X86_INS_ENDING;
  } else if constexpr (Arch::architecture_id == ArchitectureId::kAArch64) {
    arch = CS_ARCH_ARM64;
    mode = CS_MODE_ARM;
    num_instruction_ids_ = ARM64_INS_ENDING;
  } else {
    LOG_FATAL("Bad arch_id");
  }
  CHECK_EQ(cs_open(arch, mode, &capstone_handle_), CS_ERR_OK);
  // TODO(ncbray): turn this on when it's needed.
  // CHECK_EQ(cs_option(capstone_handle_, CS_OPT_DETAIL, CS_OPT_ON), CS_ERR_OK);
  decoded_insn_ = cs_malloc(capstone_handle_);
}

template <typename Arch>
CapstoneDisassembler<Arch>::~CapstoneDisassembler() {
  cs_free(decoded_insn_, 1);
  CHECK_EQ(cs_close(&capstone_handle_), CS_ERR_OK);
}

template <typename Arch>
bool CapstoneDisassembler<Arch>::Disassemble(uint64_t address,
                                             const uint8_t* buffer,
                                             size_t buffer_size) {
  // We use cs_disam_iter because it allows us to pre-allocate the buffer for
  // the decoded instruction. Note that this call will mutate `address`,
  // `buffer`, and `buffer_size` but this should not be visible to the caller.
  valid_ = cs_disasm_iter(capstone_handle_, &buffer, &buffer_size, &address,
                          decoded_insn_);
  return valid_;
}

template <typename Arch>
size_t CapstoneDisassembler<Arch>::InstructionSize() const {
  return valid_ ? decoded_insn_->size : 0;
}

template <typename Arch>
std::string CapstoneDisassembler<Arch>::FullText() const {
  return valid_
             ? absl::StrCat(decoded_insn_->mnemonic, " ", decoded_insn_->op_str)
             : "unknown";
}

template <typename Arch>
uint32_t CapstoneDisassembler<Arch>::InstructionID() const {
  return valid_ ? decoded_insn_->id : InvalidInstructionID();
}

template <typename Arch>
uint32_t CapstoneDisassembler<Arch>::InvalidInstructionID() const {
  return std::numeric_limits<uint32_t>::max();
}

template <typename Arch>
uint32_t CapstoneDisassembler<Arch>::NumInstructionIDs() const {
  return num_instruction_ids_;
}

template <typename Arch>
const char* CapstoneDisassembler<Arch>::InstructionIDName(uint32_t id) const {
  return cs_insn_name(capstone_handle_, id);
}

template class CapstoneDisassembler<X86_64>;
template class CapstoneDisassembler<AArch64>;

}  // namespace silifuzz
