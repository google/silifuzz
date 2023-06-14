// Copyright 2022 The SiliFuzz Authors.
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

#include "./common/decoded_insn.h"

#include <sys/ptrace.h>
#include <sys/user.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <string>

#include "absl/base/call_once.h"
#include "absl/base/macros.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./common/snapshot.h"
#include "./util/checks.h"
#include "./util/itoa.h"
#include "./util/misc_util.h"

extern "C" {
#include "third_party/libxed/xed-agen.h"
#include "third_party/libxed/xed-error-enum.h"
#include "third_party/libxed/xed-iclass-enum.h"
#include "third_party/libxed/xed-iform-enum.h"
#include "third_party/libxed/xed-reg-class.h"
#include "third_party/libxed/xed-reg-enum.h"
#include "third_party/libxed/xed-syntax-enum.h"
};

namespace silifuzz {

namespace {
absl::once_flag xed_initialized_once_;

// Max length of an x86_64 instruction.
// https://stackoverflow.com/questions/14698350/x86-64-asm-maximum-bytes-for-an-instruction
constexpr int kMaxX86InsnLength = 15;

// Initialized under control of xed_initialized_once_.
size_t l1_cache_line_size;

}  // namespace

DecodedInsn::DecodedInsn(const Snapshot::MemoryBytes& data) {
  status_ = Decode({data.byte_values().data(), data.num_bytes()},
                   data.start_address());
  if (!status_.ok()) LOG_ERROR(status_.message());
}

DecodedInsn::DecodedInsn(absl::string_view data, uint64_t address) {
  status_ = Decode(data, address);
  if (!status_.ok()) LOG_ERROR(status_.message());
}

bool DecodedInsn::is_deterministic() const {
  DCHECK_STATUS(status_);
  xed_iclass_enum_t iclass = xed_decoded_inst_get_iclass(&xed_insn_);
  switch (iclass) {
    case XED_ICLASS_RDRAND:
    case XED_ICLASS_RDSEED:
    case XED_ICLASS_RDTSC:
    case XED_ICLASS_RDTSCP:
    case XED_ICLASS_RDPID:
    case XED_ICLASS_CPUID:
      return false;
    case XED_ICLASS_SYSCALL:
    case XED_ICLASS_SYSENTER:
    case XED_ICLASS_INT:
    case XED_ICLASS_INT1:
    case XED_ICLASS_INTO:
      return false;
    case XED_ICLASS_WRFSBASE:
    case XED_ICLASS_WRGSBASE:
    case XED_ICLASS_RDFSBASE:
    case XED_ICLASS_RDGSBASE:
    case XED_ICLASS_XGETBV:
      // These are deterministic in the mathematical sense. However, they touch
      // registers that cannot be read/written without a syscall and are
      // therefore not allowed in SiliFuzz.
      return false;
    case XED_ICLASS_FNSAVE:
    case XED_ICLASS_FXSAVE:
    case XED_ICLASS_FXSAVE64:
    case XED_ICLASS_XSAVE:
    case XED_ICLASS_XSAVE64:
    case XED_ICLASS_XSAVEC:
    case XED_ICLASS_XSAVEC64:
    case XED_ICLASS_XSAVEOPT:
    case XED_ICLASS_XSAVEOPT64:
    case XED_ICLASS_XSAVES:
    case XED_ICLASS_XSAVES64:
    case XED_ICLASS_FLDENV:
    case XED_ICLASS_FLDCW:
    case XED_ICLASS_FNSTENV:
    case XED_ICLASS_FNSTSW:
    case XED_ICLASS_FXRSTOR:
    case XED_ICLASS_FRSTOR:
    case XED_ICLASS_FXRSTOR64:
    case XED_ICLASS_XRSTOR:
    case XED_ICLASS_XRSTORS:
    case XED_ICLASS_XRSTOR64:
      // These insns cause spurious {REGISTER,MEMORY}_MISMATCH failures. See
      // b/231974502
      return false;
    // Segment descriptor related instructions.
    // We cannot control contents of the segment descriptor tables.
    // So these produce non-deterministic results.
    case XED_ICLASS_ARPL:
    case XED_ICLASS_LAR:
    case XED_ICLASS_LSL:
    case XED_ICLASS_SIDT:
    case XED_ICLASS_SGDT:
    case XED_ICLASS_SLDT:
    case XED_ICLASS_SMSW:
    case XED_ICLASS_STR:
    case XED_ICLASS_VERR:
    case XED_ICLASS_VERW:
      // Non-deterministic but also controlled by CR4.UMIP disables these on
      // newer platforms.
      return false;
    case XED_ICLASS_XBEGIN:
    case XED_ICLASS_XEND:
    case XED_ICLASS_XABORT:
    case XED_ICLASS_MWAIT:
    case XED_ICLASS_MWAITX:
    case XED_ICLASS_MONITOR:
    case XED_ICLASS_MONITORX:
      return false;
    default:
      return true;
  }
}

bool DecodedInsn::is_locking() const {
  DCHECK_STATUS(status_);
  return xed_decoded_inst_get_attribute(&xed_insn_, XED_ATTRIBUTE_LOCKED) != 0;
}

bool DecodedInsn::is_rep_byte_store() const {
  DCHECK_STATUS(status_);
  xed_iclass_enum_t iclass = xed_decoded_inst_get_iclass(&xed_insn_);
  return iclass == XED_ICLASS_REP_MOVSB || iclass == XED_ICLASS_REP_STOSB;
}

uint8_t DecodedInsn::rex_bits() const {
  DCHECK_STATUS(status_);
  if (xed3_operand_get_rex(&xed_insn_) != 0) {
    const uint8_t w = xed3_operand_get_rexw(&xed_insn_) ? kRexW : 0;
    const uint8_t r = xed3_operand_get_rexr(&xed_insn_) ? kRexR : 0;
    const uint8_t x = xed3_operand_get_rexx(&xed_insn_) ? kRexX : 0;
    const uint8_t b = xed3_operand_get_rexb(&xed_insn_) ? kRexB : 0;
    return w | r | x | b;
  } else {
    return 0;
  }
}

absl::StatusOr<bool> DecodedInsn::may_have_split_lock(
    const struct user_regs_struct& regs) {
  DCHECK_STATUS(status_);
  if (!is_locking()) return false;

  // We expect only 1 memory operand.  Bail out if this is not the case.
  if (xed_decoded_inst_number_of_memory_operands(&xed_insn_) != 1) return false;

  ASSIGN_OR_RETURN_IF_NOT_OK(uint64_t address, memory_operand_address(0, regs));

  // For bit test instructions, the effective address is determined by both
  // bit base and bit offset. See Bit(BitBase, BitOffset) in 3.1.1.9 Operation
  // Section, vol 2. Intel 64 and IA-32 Architecture SDM for details.
  const xed_iclass_enum_t iclass = xed_decoded_inst_get_iclass(&xed_insn_);
  if (iclass == XED_ICLASS_BTC_LOCK || iclass == XED_ICLASS_BTR_LOCK ||
      iclass == XED_ICLASS_BTS_LOCK) {
    const xed_iform_enum_t iform = xed_decoded_inst_get_iform_enum(&xed_insn_);
    const uint64_t operand_bit_size =
        xed_decoded_inst_get_operand_width(&xed_insn_);
    const uint64_t operand_bit_size_mask = operand_bit_size - 1;
    uint64_t bit_offset = 0;
    switch (iform) {
      case XED_IFORM_BTC_LOCK_MEMv_GPRv:
      case XED_IFORM_BTR_LOCK_MEMv_GPRv:
      case XED_IFORM_BTS_LOCK_MEMv_GPRv: {
        xed_reg_enum_t reg =
            xed_decoded_inst_get_reg(&xed_insn_, XED_OPERAND_REG0);
        auto value_or = get_reg(reg, regs);
        RETURN_IF_NOT_OK(value_or.status());
        // A register bit value is interpreted as a signed integer of the
        // operand bit size. Here we treat it as unsigned. This is okay as we
        // only care about the lower bits up to cache line size in bits.
        bit_offset = value_or.value();
        break;
      }
      case XED_IFORM_BTC_LOCK_MEMv_IMMb:
      case XED_IFORM_BTR_LOCK_MEMv_IMMb:
      case XED_IFORM_BTS_LOCK_MEMv_IMMb:
        // We are being conservative here as it is not clear in XED's
        // documentation if xed_decode_inst_get_unsigned_immediate() fails when
        // immediate is signed. This may be unnecessary.
        if (xed_decoded_inst_get_immediate_is_signed(&xed_insn_)) {
          return absl::InternalError(
              absl::StrCat("Unexpected signed immediate in iform ",
                           xed_iform_enum_t2str(iform)));
        }

        // Immediate bits beyond operand width are not used.
        bit_offset = xed_decoded_inst_get_unsigned_immediate(&xed_insn_) &
                     operand_bit_size_mask;
        break;
      default:
        return absl::InternalError(
            absl::StrCat("Unexpected iform: ", xed_iform_enum_t2str(iform)));
    }

    // Round bit offset to multiples of operand bit size first to compute
    // the byte offset from bit base.
    const uint64_t byte_offset =
        ((bit_offset / operand_bit_size) * operand_bit_size) / 8;
    address += byte_offset;
  }

  const uint64_t offset = address & (l1_cache_line_size - 1);
  const uint64_t operand_size =
      xed_decoded_inst_get_memory_operand_length(&xed_insn_, 0);
  return offset + operand_size > l1_cache_line_size;
}

std::string DecodedInsn::mnemonic() const {
  DCHECK_STATUS(status_);
  xed_iclass_enum_t iclass = xed_decoded_inst_get_iclass(&xed_insn_);
  return xed_iclass_enum_t2str(iclass);
}

void DecodedInsn::InitXed() {
  auto init = []() {
    xed_tables_init();
    // The callbacks are global and visible to all xed clients.
    xed_agen_register_callback(agen_reg_callback, agen_segment_callback);

    // get L1 cache line size. It should a power of 2.
    l1_cache_line_size = sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
    DCHECK_GE(l1_cache_line_size, 0);
    DCHECK_EQ(l1_cache_line_size & (l1_cache_line_size - 1), 0);
  };
  absl::call_once(xed_initialized_once_, init);
}

absl::Status DecodedInsn::Decode(absl::string_view data,
                                 uint64_t start_address) {
  InitXed();
  xed_decoded_inst_zero(&xed_insn_);
  xed_decoded_inst_set_mode(&xed_insn_, XED_MACHINE_MODE_LONG_64,
                            XED_ADDRESS_WIDTH_64b);
  xed_error_enum_t xed_error = xed_decode(
      &xed_insn_, reinterpret_cast<const uint8_t*>(data.data()), data.length());
  if (xed_error != XED_ERROR_NONE) {
    return absl::InvalidArgumentError(xed_error_enum_t2str(xed_error));
  }
  if (!xed_decoded_inst_valid(&xed_insn_)) {
    return absl::InternalError("!xed_decoded_inst_valid");
  }

  xed_print_info_t pi;
  xed_init_print_info(&pi);
  pi.p = &xed_insn_;
  pi.buf = formatted_insn_buf_;
  pi.blen = sizeof(formatted_insn_buf_) - 1;
  pi.context = nullptr;
  pi.disassembly_callback = 0;
  pi.runtime_address = start_address;
  pi.syntax = XED_SYNTAX_INTEL;
  pi.format_options_valid = false;
  pi.buf[0] = 0;

  if (!xed_format_generic(&pi)) {
    return absl::InternalError("!xed_format_generic, buffer too small?");
  }
  return absl::OkStatus();
}

absl::StatusOr<Snapshot::MemoryBytes> DecodedInsn::FetchInstruction(
    pid_t pid, Snapshot::Address addr) {
  uint64_t buf[2] = {};
  static_assert(sizeof(buf) >= kMaxX86InsnLength);
  // TODO(ksteuck): [as-needed] can also consider reading /proc/$pid/mem or
  // process_vm_readv or even read the data from the snapshot. SiliFuzz infra
  // isn't suited to handle self-modifying code so reading from a static
  // snapshot is fine (except for any fixups applied by harness or Snapshot).
  //
  // We don't know the size of the instruction and attempt to
  // opportunistically PEEK as many words as possible to fill up `buf`.
  for (int i = 0; i < ABSL_ARRAYSIZE(buf); ++i) {
    uint64_t read_addr = addr + sizeof(buf[0]) * i;
    buf[i] = ptrace(PTRACE_PEEKTEXT, pid, AsPtr(read_addr), nullptr);
    if (errno != 0) {
      // TODO(ksteuck): [impl] PEEKTEXT fails at a page boundary if the
      // following page is not mapped. In this case we should break a single
      // read into two reads or/and cross-check with the mappings available in
      // the snapshot.
      return absl::InternalError(absl::StrCat(
          HexStr(read_addr), " was not mapped: ", ErrnoStr(errno)));
    }
  }
  return Snapshot::MemoryBytes(
      addr, Snapshot::ByteData(reinterpret_cast<const char*>(buf),
                               kMaxX86InsnLength));
}

// static
absl::StatusOr<uint64_t> DecodedInsn::get_reg(
    xed_reg_enum_t reg, const struct user_regs_struct& regs) {
  InitXed();
  // Handle FS and GS segments.  The rest are all GPRs.
  switch (reg) {
    case XED_REG_FSBASE:
      return regs.fs_base;
    case XED_REG_GSBASE:
      return regs.gs_base;
    default:
      break;
  }

  // Find the widest enclosing register so that we can map that to
  // those in user_regs_struct.
  xed_reg_enum_t widest_reg = xed_get_largest_enclosing_register(reg);
  uint64_t value;
  switch (widest_reg) {
    case XED_REG_RAX:
      value = regs.rax;
      break;
    case XED_REG_RCX:
      value = regs.rcx;
      break;
    case XED_REG_RDX:
      value = regs.rdx;
      break;
    case XED_REG_RBX:
      value = regs.rbx;
      break;
    case XED_REG_RSP:
      value = regs.rsp;
      break;
    case XED_REG_RBP:
      value = regs.rbp;
      break;
    case XED_REG_RSI:
      value = regs.rsi;
      break;
    case XED_REG_RDI:
      value = regs.rdi;
      break;
    case XED_REG_R8:
      value = regs.r8;
      break;
    case XED_REG_R9:
      value = regs.r9;
      break;
    case XED_REG_R10:
      value = regs.r10;
      break;
    case XED_REG_R11:
      value = regs.r11;
      break;
    case XED_REG_R12:
      value = regs.r12;
      break;
    case XED_REG_R13:
      value = regs.r13;
      break;
    case XED_REG_R14:
      value = regs.r14;
      break;
    case XED_REG_R15:
      value = regs.r15;
      break;
    case XED_REG_RIP:
      value = regs.rip;
      break;
    default:
      return absl::InvalidArgumentError(
          absl::StrCat("Invalid register ", xed_reg_enum_t2str(reg)));
  }

  // High byte registers need special handling.
  switch (reg) {
    case XED_REG_AH:
    case XED_REG_CH:
    case XED_REG_DH:
    case XED_REG_BH:
      value >>= 8;
      break;
    default:
      break;
  }

  const uint32_t width = xed_get_register_width_bits64(reg);
  CHECK_NE(width, 0) << xed_reg_enum_t2str(reg) << " has zero width";
  const uint64_t mask = ~static_cast<uint64_t>(0) >> (64 - width);
  return value & mask;
}

// static
xed_uint64_t DecodedInsn::agen_reg_callback(xed_reg_enum_t reg, void* context,
                                            xed_bool_t* error) {
  DCHECK(context != nullptr);
  struct user_regs_struct* regs =
      reinterpret_cast<struct user_regs_struct*>(context);
  absl::StatusOr<uint64_t> value_or = get_reg(reg, *regs);
  *error = !value_or.ok();
  return value_or.ok() ? value_or.value() : 0;
}

// static
xed_uint64_t DecodedInsn::agen_segment_callback(xed_reg_enum_t reg,
                                                void* context,
                                                xed_bool_t* error) {
  DCHECK(context != nullptr);
  xed_reg_enum_t base_reg = XED_REG_INVALID;
  *error = false;
  switch (reg) {
    case XED_REG_CS:
    case XED_REG_SS:
    case XED_REG_DS:
    case XED_REG_ES:
      // In 64-bit mode, these segments are zero-based.
      return 0;
    case XED_REG_FS:
      base_reg = XED_REG_FSBASE;
      break;
    case XED_REG_GS:
      base_reg = XED_REG_GSBASE;
      break;
    default:
      *error = true;
      return 0;
  }

  struct user_regs_struct* regs =
      reinterpret_cast<struct user_regs_struct*>(context);
  absl::StatusOr<uint64_t> value_or = get_reg(base_reg, *regs);
  *error = !value_or.ok();
  return value_or.ok() ? value_or.value() : 0;
}

absl::StatusOr<uint64_t> DecodedInsn::memory_operand_address(
    size_t i, const struct user_regs_struct& regs) {
  DCHECK_STATUS(status_);
  xed_uint64_t address;

  // For RIP-relative addressing, we need the address after this instruction.
  // So make a copy of `regs` and fix up RIP there.
  user_regs_struct regs_with_adjusted_rip = regs;
  regs_with_adjusted_rip.rip += xed_decoded_inst_get_length(&xed_insn_);
  xed_error_enum_t error = xed_agen(
      &xed_insn_, i,
      const_cast<struct user_regs_struct*>(&regs_with_adjusted_rip), &address);
  if (error == XED_ERROR_NONE) {
    return address;
  } else {
    return absl::InternalError(
        absl::StrCat("xed_agen: ", xed_error_enum_t2str(error)));
  }
}

}  // namespace silifuzz
