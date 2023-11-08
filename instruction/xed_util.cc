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

#include "./instruction/xed_util.h"

#include <cstddef>
#include <cstdint>

#include "absl/base/call_once.h"

extern "C" {
#include "third_party/libxed/xed-category-enum.h"
#include "third_party/libxed/xed-decoded-inst-api.h"
#include "third_party/libxed/xed-decoded-inst.h"
#include "third_party/libxed/xed-iclass-enum.h"
#include "third_party/libxed/xed-init.h"
#include "third_party/libxed/xed-inst.h"
#include "third_party/libxed/xed-print-info.h"
#include "third_party/libxed/xed-syntax-enum.h"
}

namespace silifuzz {

absl::once_flag xed_init_once;

void InitXedIfNeeded() {
  // It should be safe to call xed_tables_init multiple times from a single
  // thread (the implementation checks if it's been called before) but it
  // doesn't look safe if it's being called by multiple threads at the same
  // time.
  absl::call_once(xed_init_once, xed_tables_init);
}

bool FormatInstruction(const xed_decoded_inst_t& instruction, uint64_t address,
                       char* buffer, size_t buffer_size) {
  xed_print_info_t pi;
  xed_init_print_info(&pi);
  pi.p = &instruction;
  pi.buf = buffer;
  // XED does not check the null terminator falls inside the buffer, this size
  // is effectively the size of the text.
  pi.blen = buffer_size - 1;
  pi.context = nullptr;
  pi.disassembly_callback = nullptr;
  pi.runtime_address = address;
  pi.syntax = XED_SYNTAX_INTEL;
  pi.format_options_valid = false;
  pi.buf[0] = 0;
  return xed_format_generic(&pi);
}

bool InstructionIsDeterministicInRunner(const xed_decoded_inst_t& instruction) {
  xed_iclass_enum_t iclass = xed_decoded_inst_get_iclass(&instruction);
  switch (iclass) {
    case XED_ICLASS_RDPID:
    case XED_ICLASS_RDRAND:
    case XED_ICLASS_RDSEED:
    case XED_ICLASS_RDTSC:
    case XED_ICLASS_RDTSCP:
      return false;
    case XED_ICLASS_CPUID:
    case XED_ICLASS_RDFSBASE:
    case XED_ICLASS_RDGSBASE:
    case XED_ICLASS_RDMSR:
    case XED_ICLASS_RDMSRLIST:
    case XED_ICLASS_RDPKRU:
    case XED_ICLASS_RDPMC:
    case XED_ICLASS_RDPRU:
    case XED_ICLASS_RDSSPD:
    case XED_ICLASS_RDSSPQ:
    case XED_ICLASS_WRFSBASE:
    case XED_ICLASS_WRGSBASE:
    case XED_ICLASS_WRMSR:
    case XED_ICLASS_WRMSRLIST:
    case XED_ICLASS_WRMSRNS:
    case XED_ICLASS_WRPKRU:
    case XED_ICLASS_WRSSD:
    case XED_ICLASS_WRSSQ:
    case XED_ICLASS_WRUSSD:
    case XED_ICLASS_WRUSSQ:
    case XED_ICLASS_XGETBV:
      // These are deterministic in the mathematical sense. However, they touch
      // registers that either cannot or are not currently preserved as part of
      // the UContext struct.
      // Such instructions can and often do cause false positives.
      return false;
    case XED_ICLASS_SYSCALL:
    case XED_ICLASS_SYSENTER:
    case XED_ICLASS_INT:
    case XED_ICLASS_INT1:
    case XED_ICLASS_INTO:
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
    case XED_ICLASS_TPAUSE:
    case XED_ICLASS_UMWAIT:
    case XED_ICLASS_UMONITOR:
      return false;
    default:
      return true;
  }
}

bool InstructionCanRunInUserSpace(const xed_decoded_inst_t& instruction) {
  return xed_inst_cpl(xed_decoded_inst_inst(&instruction)) >= 3;
}

bool InstructionRequiresIOPrivileges(const xed_decoded_inst_t& instruction) {
  xed_category_enum_t category = xed_decoded_inst_get_category(&instruction);
  return category == XED_CATEGORY_IO || category == XED_CATEGORY_IOSTRINGOP;
}

}  // namespace silifuzz
