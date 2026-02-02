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
#include "./util/platform.h"

extern "C" {
#include "third_party/libxed/xed-interface.h"
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

bool InstructionIsAllowedInRunner(const xed_inst_t* instruction) {
  return InstructionClassIsAllowedInRunner(instruction) &&
         InstructionExtensionIsAllowedInRunner(instruction) &&
         InstructionCanRunInUserSpace(instruction) &&
         !InstructionRequiresIOPrivileges(instruction);
}

bool InstructionClassIsAllowedInRunner(const xed_inst_t* instruction) {
  switch (xed_inst_iclass(instruction)) {
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
    case XED_ICLASS_SYSCALL_AMD:
    case XED_ICLASS_SYSENTER:
    case XED_ICLASS_SYSEXIT:
    case XED_ICLASS_SYSRET:
    case XED_ICLASS_SYSRET64:
    case XED_ICLASS_SYSRET_AMD:
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
    case XED_ICLASS_ENTER:
      // Quick fix for b/377197728.
      return false;
    default:
      return true;
  }
}

bool InstructionExtensionIsAllowedInRunner(const xed_inst_t* instruction) {
  switch (xed_inst_extension(instruction)) {
    case XED_EXTENSION_AMX_TILE:
      // These are AMX instructions that we do not plan to support (b/432543671)
      return false;
    default:
      return true;
  }
}

bool InstructionCanRunInUserSpace(const xed_inst_t* instruction) {
  return xed_inst_cpl(instruction) >= 3;
}

bool InstructionRequiresIOPrivileges(const xed_inst_t* instruction) {
  xed_category_enum_t category = xed_inst_category(instruction);
  return category == XED_CATEGORY_IO || category == XED_CATEGORY_IOSTRINGOP;
}

bool InstructionIsBranch(const xed_inst_t* instruction) {
  xed_category_enum_t category = xed_inst_category(instruction);
  return category == XED_CATEGORY_CALL || category == XED_CATEGORY_COND_BR ||
         category == XED_CATEGORY_RET || category == XED_CATEGORY_UNCOND_BR;
}

bool InstructionIsX87(const xed_inst_t* instruction) {
  return xed_inst_extension(instruction) == XED_EXTENSION_X87;
}

bool InstructionIsSSE(const xed_inst_t* instruction) {
  xed_extension_enum_t ext = xed_inst_extension(instruction);
  return ext == XED_EXTENSION_SSE || ext == XED_EXTENSION_SSE2 ||
         ext == XED_EXTENSION_SSE3 || ext == XED_EXTENSION_SSE4 ||
         ext == XED_EXTENSION_SSE4A || ext == XED_EXTENSION_SSSE3;
}

bool InstructionIsAVX512EVEX(const xed_inst_t* instruction) {
  return xed_inst_extension(instruction) == XED_EXTENSION_AVX512EVEX;
}

bool InstructionIsAMX(const xed_inst_t* instruction) {
  xed_extension_enum_t extension = xed_inst_extension(instruction);
  return extension == XED_EXTENSION_AMX_TILE;
}

// Note: we use the "server" versions of each chips because we're primarily
// targeting the data center. This may skew with desktops.
xed_chip_enum_t PlatformIdToChip(PlatformId platform_id) {
  switch (platform_id) {
    case PlatformId::kIntelSkylake:
      return XED_CHIP_SKYLAKE_SERVER;
    case PlatformId::kIntelHaswell:
      return XED_CHIP_HASWELL;
    case PlatformId::kIntelBroadwell:
      return XED_CHIP_BROADWELL;
    case PlatformId::kIntelIvybridge:
      return XED_CHIP_IVYBRIDGE;
    case PlatformId::kIntelCascadelake:
      return XED_CHIP_CASCADE_LAKE;
    case PlatformId::kAmdRome:
    case PlatformId::kAmdRyzenV3000:
      return XED_CHIP_AMD_ZEN2;
    case PlatformId::kIntelIcelake:
      return XED_CHIP_ICE_LAKE_SERVER;
    case PlatformId::kAmdMilan:
      // Should be ZEN3?
      return XED_CHIP_AMD_FUTURE;
    case PlatformId::kIntelSapphireRapids:
      return XED_CHIP_SAPPHIRE_RAPIDS;
    case PlatformId::kAmdGenoa:
    case PlatformId::kAmdSiena:
      // Should be ZEN4?
      return XED_CHIP_AMD_FUTURE;
    case PlatformId::kAmdTurin:
      // Should be ZEN5?
      return XED_CHIP_AMD_FUTURE;
    case PlatformId::kAmdVenice:
      // Should be ZEN6?
      return XED_CHIP_AMD_FUTURE;
    case PlatformId::kIntelCoffeelake:
      // In this era of Intel chips, different process nodes were given
      // different code names. XED does not have enums for these names, however.
      // A cursory investigation shows that Coffeelake should support the same
      // instructions as Skylake.
      return XED_CHIP_SKYLAKE;
    case PlatformId::kIntelAlderlake:
      return XED_CHIP_ALDER_LAKE;
    case PlatformId::kIntelEmeraldRapids:
      return XED_CHIP_EMERALD_RAPIDS;
    case PlatformId::kIntelGraniteRapids:
      return XED_CHIP_GRANITE_RAPIDS;
    default:
      return XED_CHIP_INVALID;
  }
}

unsigned int ChipVectorRegisterWidth(xed_chip_enum_t chip) {
  if (xed_isa_set_is_valid_for_chip(XED_ISA_SET_AVX512F_512, chip)) {
    return 512;
  }
  if (xed_isa_set_is_valid_for_chip(XED_ISA_SET_AVX2, chip)) {
    return 256;
  }
  if (xed_isa_set_is_valid_for_chip(XED_ISA_SET_SSE, chip)) {
    return 128;
  }
  return 0;
}

unsigned int ChipMaskRegisterWidth(xed_chip_enum_t chip) {
  if (xed_isa_set_is_valid_for_chip(XED_ISA_SET_AVX512BW_KOPQ, chip)) {
    return 64;
  }
  // TODO(ncbray): Is there any chip in existence with KOPD but not KOPQ?
  if (xed_isa_set_is_valid_for_chip(XED_ISA_SET_AVX512BW_KOPD, chip)) {
    return 32;
  }
  // Note: it's unlikely to encounter chips with a 16-bit mask in a data center.
  if (xed_isa_set_is_valid_for_chip(XED_ISA_SET_AVX512F_KOPW, chip)) {
    return 16;
  }
  // Chip does not support AVX512.
  return 0;
}

bool InstructionBuilder::Encode(uint8_t* buf, size_t& len) {
  xed_state_t dstate;
  xed_state_init2(&dstate, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

  xed_encoder_instruction_t enc;
  xed_inst(&enc, dstate, iclass_, effective_op_width_, num_operands_,
           operands_);

  xed_encoder_request_t req;
  xed_encoder_request_zero_set_mode(&req, &dstate);
  if (!xed_convert_to_encoder_request(&req, &enc)) {
    return false;
  }

  unsigned int tmp_len = len;
  xed_error_enum_t res = xed_encode(&req, buf, len, &tmp_len);
  len = tmp_len;
  return res == XED_ERROR_NONE;
}

}  // namespace silifuzz
