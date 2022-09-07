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

#include "absl/base/call_once.h"
#include "absl/base/macros.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./common/snapshot.h"
#include "./util/checks.h"
#include "./util/itoa.h"

extern "C" {
#include "third_party/libxed/xed-iclass-enum.h"
#include "third_party/libxed/xed-syntax-enum.h"
};

namespace silifuzz {

namespace {
absl::once_flag xed_initialized_once_;

// Max length of an x86_64 instruction.
// https://stackoverflow.com/questions/14698350/x86-64-asm-maximum-bytes-for-an-instruction
constexpr int kMaxX86InsnLength = 15;
}  // namespace

DecodedInsn::DecodedInsn(const Snapshot::MemoryBytes& data) {
  status_ = Decode({data.byte_values().data(), data.num_bytes()},
                   data.start_address());
  if (!status_.ok()) LOG_ERROR(status_.message());
}

DecodedInsn::DecodedInsn(absl::string_view data) {
  status_ = Decode(data);
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
    case XED_ICLASS_SIDT:
    case XED_ICLASS_SGDT:
    case XED_ICLASS_SLDT:
    case XED_ICLASS_SMSW:
    case XED_ICLASS_STR:
      // Non-deterministic but also controlled by CR4.UMIP disables these on
      // newer platforms.
      return false;
    default:
      return true;
  }
}

std::string DecodedInsn::mnemonic() const {
  DCHECK_STATUS(status_);
  xed_iclass_enum_t iclass = xed_decoded_inst_get_iclass(&xed_insn_);
  return xed_iclass_enum_t2str(iclass);
}

absl::Status DecodedInsn::Decode(absl::string_view data,
                                 uint64_t start_address) {
  absl::call_once(xed_initialized_once_, xed_tables_init);
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
  pi.blen = sizeof(formatted_insn_buf_);
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
}  // namespace silifuzz
