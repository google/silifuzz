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

#include <cinttypes>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "./common/proxy_config.h"
#include "./common/raw_insns_util.h"
#include "./common/snapshot.h"
#include "./common/snapshot_util.h"
#include "./util/arch_mem.h"
#include "./util/checks.h"
#include "./util/itoa.h"
#include "./util/logging_util.h"
#include "./util/ucontext/ucontext.h"
#include "third_party/unicorn/arm64.h"
#include "third_party/unicorn/unicorn.h"

namespace silifuzz {

namespace {

// Drops the privlege level to EL0
//
// Don't trap advanced SIMD or floating point in EL0 or EL1.
// Note: will trap SVE.
// d2a00600  mov x0, #0x300000
// d5181040  msr cpacr_el1, x0
// TODO(ncbray): configure SCTLR_EL1
// Configure the state upon returning to EL0.
// TODO(ncbray): set nzcv, etc.
// aa1f03e0  mov x0, xzr
// d5184000  msr spsr_el1, x0
// Jump to x30 upon returning to EL0.
// d518403e  msr elr_el1, x30
// Return to EL0.
// d69f03e0  eret

constexpr uint32_t kEntrySequence[] = {
    0xd2a00600, 0xd5181040, 0xaa1f03e0, 0xd5184000, 0xd518403e, 0xd69f03e0,
};

// Use an address outside the configured memory ranges.
constexpr uint64_t kEntrySequenceAddress = 0x123'4567'0000;

#define UNICORN_CHECK(...)                              \
  do {                                                  \
    uc_err __uc_check_err = __VA_ARGS__;                \
    if ((__uc_check_err != UC_ERR_OK)) {                \
      LOG_FATAL(#__VA_ARGS__ " failed with ",           \
                silifuzz::IntStr(__uc_check_err), ": ", \
                uc_strerror(__uc_check_err));           \
    }                                                   \
  } while (0);

void map_memory(uc_engine *uc, uint64_t addr, uint64_t size, uint32_t prot) {
  uc_err err = uc_mem_map(uc, addr, size, prot);
  if (err != UC_ERR_OK) {
    LOG_FATAL("mapping ", HexStr(addr), " failed with ", IntStr(err), ": ",
              uc_strerror(err));
  }
}

uint32_t MemoryPermsToUnicorn(const MemoryPerms &perms) {
  uint32_t prot = 0;
  if (perms.Has(MemoryPerms::kReadable)) {
    prot |= UC_PROT_READ;
  }
  if (perms.Has(MemoryPerms::kWritable)) {
    prot |= UC_PROT_WRITE;
  }
  if (perms.Has(MemoryPerms::kExecutable)) {
    prot |= UC_PROT_EXEC;
  }
  return prot;
}

void SetupCPUState(uc_engine *uc) {
  // Inject the entry sequence.
  map_memory(uc, kEntrySequenceAddress, 0x1000, UC_PROT_EXEC);
  UNICORN_CHECK(uc_mem_write(uc, kEntrySequenceAddress, kEntrySequence,
                             sizeof(kEntrySequence)));

  // The entry sequence needs to ERET to somewhere mapped, choose just after the
  // entry sequence.
  uint64_t exit_address = kEntrySequenceAddress + sizeof(kEntrySequence);
  UNICORN_CHECK(uc_reg_write(uc, UC_ARM64_REG_X30, &exit_address));

  // Execute the entry seqeunce
  UNICORN_CHECK(uc_emu_start(uc, kEntrySequenceAddress, exit_address, 0, 100));

  // Unmap the entry sequence
  UNICORN_CHECK(uc_mem_unmap(uc, kEntrySequenceAddress, 0x1000));
}

void SetupMemory(const Snapshot &snapshot, uc_engine *uc, bool log = false) {
  for (const Snapshot::MemoryMapping &mm : snapshot.memory_mappings()) {
    if (log) {
      LOG_INFO("MemoryMapping ", HexStr(mm.start_address()), " / ",
               mm.num_bytes(), " / ", mm.perms().DebugString());
    }
    map_memory(uc, mm.start_address(), mm.num_bytes(),
               MemoryPermsToUnicorn(mm.perms()));
  }

  for (const Snapshot::MemoryBytes &mb : snapshot.memory_bytes()) {
    if (log) {
      LOG_INFO("MemoryBytes ", HexStr(mb.start_address()), " / ",
               mb.num_bytes());
    }
    const Snapshot::ByteData &data = mb.byte_values();
    UNICORN_CHECK(
        uc_mem_write(uc, mb.start_address(), data.data(), data.size()));
  }

  // Simulate the effect RestoreUContext could have on the stack.
  GRegSet<AArch64> gregs;
  absl::Status status = ConvertRegsFromSnapshot(snapshot.registers(), &gregs);
  if (!status.ok()) {
    LOG_FATAL("Failed to deserialize registers - ", status.message());
  }
  std::string stack_bytes = RestoreUContextStackBytes(gregs);
  UNICORN_CHECK(uc_mem_write(uc, GetStackPointer(gregs) - stack_bytes.size(),
                             stack_bytes.data(), stack_bytes.size()));
}

uint64_t SetupRegisters(const Snapshot &snapshot, uc_engine *uc,
                        bool log = false) {
  GRegSet<AArch64> gregs;
  FPRegSet<AArch64> fpregs;
  absl::Status status =
      ConvertRegsFromSnapshot(snapshot.registers(), &gregs, &fpregs);
  if (!status.ok()) {
    LOG_FATAL("Failed to deserialize registers - ", status.message());
  }

  if (log) {
    GRegSet<AArch64> zero_gregs = {};
    LogGRegs(gregs, &zero_gregs, true);
    FPRegSet<AArch64> zero_fpregs = {};
    LogFPRegs(fpregs, true, &zero_fpregs, true);
  }

  int reg_names[] = {
      UC_ARM64_REG_X0,   UC_ARM64_REG_X1,        UC_ARM64_REG_X2,
      UC_ARM64_REG_X3,   UC_ARM64_REG_X4,        UC_ARM64_REG_X5,
      UC_ARM64_REG_X6,   UC_ARM64_REG_X7,        UC_ARM64_REG_X8,
      UC_ARM64_REG_X9,   UC_ARM64_REG_X10,       UC_ARM64_REG_X11,
      UC_ARM64_REG_X12,  UC_ARM64_REG_X13,       UC_ARM64_REG_X14,
      UC_ARM64_REG_X15,  UC_ARM64_REG_X16,       UC_ARM64_REG_X17,
      UC_ARM64_REG_X18,  UC_ARM64_REG_X19,       UC_ARM64_REG_X20,
      UC_ARM64_REG_X21,  UC_ARM64_REG_X22,       UC_ARM64_REG_X23,
      UC_ARM64_REG_X24,  UC_ARM64_REG_X25,       UC_ARM64_REG_X26,
      UC_ARM64_REG_X27,  UC_ARM64_REG_X28,       UC_ARM64_REG_X29,
      UC_ARM64_REG_X30,  UC_ARM64_REG_SP,        UC_ARM64_REG_PC,
      UC_ARM64_REG_NZCV, UC_ARM64_REG_TPIDR_EL0, UC_ARM64_REG_TPIDRRO_EL0,
      UC_ARM64_REG_V0,   UC_ARM64_REG_V1,        UC_ARM64_REG_V2,
      UC_ARM64_REG_V3,   UC_ARM64_REG_V4,        UC_ARM64_REG_V5,
      UC_ARM64_REG_V6,   UC_ARM64_REG_V7,        UC_ARM64_REG_V8,
      UC_ARM64_REG_V9,   UC_ARM64_REG_V10,       UC_ARM64_REG_V11,
      UC_ARM64_REG_V12,  UC_ARM64_REG_V13,       UC_ARM64_REG_V14,
      UC_ARM64_REG_V15,  UC_ARM64_REG_V16,       UC_ARM64_REG_V17,
      UC_ARM64_REG_V18,  UC_ARM64_REG_V19,       UC_ARM64_REG_V20,
      UC_ARM64_REG_V21,  UC_ARM64_REG_V22,       UC_ARM64_REG_V23,
      UC_ARM64_REG_V24,  UC_ARM64_REG_V25,       UC_ARM64_REG_V26,
      UC_ARM64_REG_V27,  UC_ARM64_REG_V28,       UC_ARM64_REG_V29,
      UC_ARM64_REG_V30,  UC_ARM64_REG_V31,
  };

  const void *reg_values[] = {
      &gregs.x[0],   &gregs.x[1],   &gregs.x[2],   &gregs.x[3],
      &gregs.x[4],   &gregs.x[5],   &gregs.x[6],   &gregs.x[7],
      &gregs.x[8],   &gregs.x[9],   &gregs.x[10],  &gregs.x[11],
      &gregs.x[12],  &gregs.x[13],  &gregs.x[14],  &gregs.x[15],
      &gregs.x[16],  &gregs.x[17],  &gregs.x[18],  &gregs.x[19],
      &gregs.x[20],  &gregs.x[21],  &gregs.x[22],  &gregs.x[23],
      &gregs.x[24],  &gregs.x[25],  &gregs.x[26],  &gregs.x[27],
      &gregs.x[28],  &gregs.x[29],  &gregs.x[30],  &gregs.sp,
      &gregs.pc,     &gregs.pstate, &gregs.tpidr,  &gregs.tpidrro,
      &fpregs.v[0],  &fpregs.v[1],  &fpregs.v[2],  &fpregs.v[3],
      &fpregs.v[4],  &fpregs.v[5],  &fpregs.v[6],  &fpregs.v[7],
      &fpregs.v[8],  &fpregs.v[9],  &fpregs.v[10], &fpregs.v[11],
      &fpregs.v[12], &fpregs.v[13], &fpregs.v[14], &fpregs.v[15],
      &fpregs.v[16], &fpregs.v[17], &fpregs.v[18], &fpregs.v[19],
      &fpregs.v[20], &fpregs.v[21], &fpregs.v[22], &fpregs.v[23],
      &fpregs.v[24], &fpregs.v[25], &fpregs.v[26], &fpregs.v[27],
      &fpregs.v[28], &fpregs.v[29], &fpregs.v[30], &fpregs.v[31],
  };
  static_assert(ABSL_ARRAYSIZE(reg_names) == ABSL_ARRAYSIZE(reg_values));

  // TODO(ncbray): set fpsr and fpcr. This will likely require patching upstream
  // Unicorn or executing ASM inside the emulator.

  // uc_reg_write_batch wants vals of type (void* const*) which is an
  // "array of const pointer to void" but it should have been "array of pointer
  // to const void" (i.e. the value under the pointer cannot change). Therefore
  // the cast.
  uc_reg_write_batch(uc, reg_names, const_cast<void *const *>(reg_values),
                     ABSL_ARRAYSIZE(reg_values));

  return gregs.pc;
}

uint64_t GetExitPoint(const Snapshot &snapshot) {
  const Snapshot::EndStateList &end_states = snapshot.expected_end_states();
  CHECK_EQ(end_states.size(), 1);
  return end_states[0].endpoint().instruction_address();
}

}  // namespace

int RunAArch64Instructions(absl::string_view insns) {
  // Require at least one instruction.
  if (insns.size() < 4) {
    return -1;
  }

  FuzzingConfig<AArch64> config = DEFAULT_AARCH64_FUZZING_CONFIG;

  absl::StatusOr<Snapshot> snapshot =
      InstructionsToSnapshot<AArch64>(insns, config);
  if (!snapshot.ok()) {
    LOG_ERROR("could not create snapshot - ", snapshot.status().message());
    // This input is likely not a multiple of 4 or too large.
    return -1;
  }

  // Initialize emulator.
  uc_engine *uc;
  UNICORN_CHECK(uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc));

  // Details to sort out later:
  // TODO(ncbray) why do atomic ops using the initial stack pointer not fault?
  // 1000000: 787f63fc ldumaxlh    wzr, w28, [sp]

  SetupCPUState(uc);

  SetupMemory(snapshot.value(), uc);

  // These mappings are currently not represented in the Snapshot.
  map_memory(uc, config.data1_range.start_address, config.data1_range.num_bytes,
             UC_PROT_READ | UC_PROT_WRITE);
  map_memory(uc, config.data2_range.start_address, config.data2_range.num_bytes,
             UC_PROT_READ | UC_PROT_WRITE);

  uint64_t start_of_code = SetupRegisters(snapshot.value(), uc);

  // Execute the instructions.
  // Stop at the exit point.
  uint64_t end_of_code = GetExitPoint(snapshot.value());
  // Stop at an arbitrary instruction count to avoid infinite loops.
  size_t max_inst_executed = 0x1000;
  uc_err err =
      uc_emu_start(uc, start_of_code, end_of_code, 0, max_inst_executed);

  bool input_is_acceptable = true;

  // Check if the emulator stopped cleanly.
  if (err) {
    LOG_ERROR("uc_emu_start() returned ", IntStr(err), ": ", uc_strerror(err));
    input_is_acceptable = false;
  }

  // Check if the emulator stopped at the right address.
  // Unicorn does not return an error if it stops executing because it reached
  // the maximum instruction count.
  uint64_t pc = 0;
  UNICORN_CHECK(uc_reg_read(uc, UC_ARM64_REG_PC, &pc));
  if (pc != end_of_code) {
    LOG_ERROR("expected PC would be ", HexStr(end_of_code), ", but got ",
              HexStr(pc), " instead");
    input_is_acceptable = false;
  }

  // aarch64 requires that stack pointers are 16-byte aligned when they are
  // used. The exit sequence will use the stack pointer, so SP needs to be
  // aligned when the instruction sequence exits.
  // Note that QEMU appears to not care about unaligned stack pointers. Hardware
  // cares, however, and this creates skew between the proxy and hardware.
  // Checking the stack pointer aligment on exit should help filter out some,
  // but not all of these problems. It will not catch situations where the stack
  // pointer is unaligned during execution, but becomes re-aligned before
  // exiting.
  uint64_t sp = 0;
  UNICORN_CHECK(uc_reg_read(uc, UC_ARM64_REG_SP, &sp));
  constexpr uint64_t kRequiredStackAlignment = 16;
  if (sp % kRequiredStackAlignment != 0) {
    LOG_ERROR("stack pointer misaligned on exit");
    input_is_acceptable = false;
  }

  uc_close(uc);

  return input_is_acceptable ? 0 : -1;
}

}  // namespace silifuzz

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  return silifuzz::RunAArch64Instructions(
      absl::string_view((const char *)data, size));
}
