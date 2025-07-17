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

#include "./instruction/capstone_disassembler.h"

#include <stdint.h>

#include <cstddef>
#include <cstring>
#include <string>

#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "third_party/capstone/arm64.h"
#include "third_party/capstone/capstone.h"
#include "third_party/capstone/x86.h"
#include "./instruction/disassembler.h"
#include "./util/arch.h"
#include "./util/checks.h"

namespace silifuzz {

namespace {

template <typename Arch>
bool InstructionCanBranch(cs_insn* decoded_insn);

template <>
bool InstructionCanBranch<X86_64>(cs_insn* decoded_insn) {
  cs_detail* detail = decoded_insn->detail;
  for (size_t i = 0; i < detail->groups_count; ++i) {
    if (detail->groups[i] == X86_GRP_JUMP ||
        detail->groups[i] == X86_GRP_CALL || detail->groups[i] == X86_GRP_RET ||
        detail->groups[i] == X86_GRP_BRANCH_RELATIVE) {
      return true;
    }
  }
  return false;
}

template <>
bool InstructionCanBranch<AArch64>(cs_insn* decoded_insn) {
  cs_detail* detail = decoded_insn->detail;
  for (size_t i = 0; i < detail->groups_count; ++i) {
    // In practice aarch64 labels all these instructions as "JUMP" but check all
    // the groups in case this changes.
    if (detail->groups[i] == ARM64_GRP_JUMP ||
        detail->groups[i] == ARM64_GRP_CALL ||
        detail->groups[i] == ARM64_GRP_RET ||
        detail->groups[i] == ARM64_GRP_BRANCH_RELATIVE) {
      return true;
    }
  }
  return false;
}

template <typename Arch>
bool InstructionCanLoad(cs_insn* decoded_insn);

template <>
bool InstructionCanLoad<X86_64>(cs_insn* decoded_insn) {
  const cs_x86& detail = decoded_insn->detail->x86;
  for (size_t i = 0; i < detail.op_count; ++i) {
    if (detail.operands[i].type == X86_OP_MEM) {
      if (detail.operands[i].access & CS_AC_READ) {
        return true;
      }
    }
  }
  return false;
}

template <>
bool InstructionCanLoad<AArch64>(cs_insn* decoded_insn) {
  const cs_arm64& detail = decoded_insn->detail->arm64;
  for (size_t i = 0; i < detail.op_count; ++i) {
    if (detail.operands[i].type == ARM64_OP_MEM) {
      // aarch64 sometimes marks pure loads or stores as load/stores.
      // Unfortunately some atomic instructions are actually load/stores, so
      // we cannot easily detect these cases without understanding the semantics
      // of the instruction.
      // For now, we just need to live with the inaccuracy.
      if (detail.operands[i].access & CS_AC_READ) {
        return true;
      }
    }
  }
  return false;
}

template <typename Arch>
bool InstructionCanStore(cs_insn* decoded_insn);

template <>
bool InstructionCanStore<X86_64>(cs_insn* decoded_insn) {
  const cs_x86& detail = decoded_insn->detail->x86;
  for (size_t i = 0; i < detail.op_count; ++i) {
    if (detail.operands[i].type == X86_OP_MEM) {
      if (detail.operands[i].access & CS_AC_WRITE) {
        return true;
      }
    }
  }
  return false;
}

template <>
bool InstructionCanStore<AArch64>(cs_insn* decoded_insn) {
  const cs_arm64& detail = decoded_insn->detail->arm64;
  for (size_t i = 0; i < detail.op_count; ++i) {
    if (detail.operands[i].type == ARM64_OP_MEM) {
      if (detail.operands[i].access & CS_AC_WRITE) {
        return true;
      }
    }
  }
  return false;
}

}  // namespace

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
  CHECK_EQ(cs_option(capstone_handle_, CS_OPT_DETAIL, CS_OPT_ON), CS_ERR_OK);
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
  const uint8_t* original_buffer = buffer;
  size_t original_buffer_size = buffer_size;
  // We use cs_disam_iter because it allows us to pre-allocate the buffer for
  // the decoded instruction. Note that this call will mutate `address`,
  // `buffer`, and `buffer_size` but this should not be visible to the caller.
  valid_ = cs_disasm_iter(capstone_handle_, &buffer, &buffer_size, &address,
                          decoded_insn_);
  if (!valid_) {
    last_invalid_buffer_size_ =
        std::min(original_buffer_size, Arch::kMaxInstructionLength);

    std::memcpy(last_invalid_buffer_.data(), original_buffer,
                last_invalid_buffer_size_);
  }
  return valid_;
}

template <typename Arch>
size_t CapstoneDisassembler<Arch>::InstructionSize() const {
  return valid_ ? decoded_insn_->size : 0;
}

template <typename Arch>
bool CapstoneDisassembler<Arch>::CanBranch() const {
  return valid_ ? InstructionCanBranch<Arch>(decoded_insn_) : false;
}

template <typename Arch>
bool CapstoneDisassembler<Arch>::CanLoad() const {
  return valid_ ? InstructionCanLoad<Arch>(decoded_insn_) : false;
}

template <typename Arch>
bool CapstoneDisassembler<Arch>::CanStore() const {
  return valid_ ? InstructionCanStore<Arch>(decoded_insn_) : false;
}

template <typename Arch>
std::string CapstoneDisassembler<Arch>::FullText() {
  if (valid_) {
    return absl::StrCat(decoded_insn_->mnemonic, " ", decoded_insn_->op_str);
  }
  return StringifyInvalidInstruction();
}

template <typename Arch>
uint32_t CapstoneDisassembler<Arch>::InstructionID() const {
  return valid_ ? decoded_insn_->id : InvalidInstructionID();
}

template <typename Arch>
uint32_t CapstoneDisassembler<Arch>::InvalidInstructionID() const {
  // There are arch-specific enums for invalid, but they are all zero.
  return 0;
}

template <typename Arch>
uint32_t CapstoneDisassembler<Arch>::NumInstructionIDs() const {
  return num_instruction_ids_;
}

template <typename Arch>
std::string CapstoneDisassembler<Arch>::InstructionIDName(uint32_t id) const {
  if (id == InvalidInstructionID()) {
    return kInvalidInstructionName;
  }
  return cs_insn_name(capstone_handle_, id);
}

template <>
std::string CapstoneDisassembler<X86_64>::StringifyInvalidInstruction() const {
  std::string invalid_bytes_hex_rep = kInvalidInstructionName;
  for (int i = 0; i < last_invalid_buffer_size_; ++i) {
    absl::StrAppend(&invalid_bytes_hex_rep,
                    absl::StrFormat(" %02x", last_invalid_buffer_[i]));
  }

  return invalid_bytes_hex_rep;
}

template <>
std::string CapstoneDisassembler<AArch64>::StringifyInvalidInstruction() const {
  // Copy the bytes into a new uint32_t to prevent unaligned access.
  uint32_t word;
  std::memcpy(&word, last_invalid_buffer_.data(), last_invalid_buffer_size_);
  return absl::StrFormat("%s %08x", kInvalidInstructionName, word);
}

template class CapstoneDisassembler<X86_64>;
template class CapstoneDisassembler<AArch64>;

}  // namespace silifuzz
