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

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

#include "absl/status/status.h"
#include "./common/proxy_config.h"
#include "./common/snapshot.h"
#include "./tracing/unicorn_tracer.h"
#include "./tracing/unicorn_util.h"
#include "./util/arch.h"
#include "./util/arch_mem.h"
#include "./util/checks.h"
#include "./util/page_util.h"
#include "./util/ucontext/ucontext_types.h"
#include "third_party/unicorn/arm64.h"
#include "third_party/unicorn/unicorn.h"

namespace silifuzz {

namespace {

// Drops the privilege level to EL0
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

void SetupCPUState(uc_engine *uc) {
  // Inject the entry sequence.
  UNICORN_CHECK(uc_mem_map(uc, kEntrySequenceAddress, kPageSize, UC_PROT_EXEC));
  UNICORN_CHECK(uc_mem_write(uc, kEntrySequenceAddress, kEntrySequence,
                             sizeof(kEntrySequence)));

  // The entry sequence needs to ERET to somewhere mapped, choose just after the
  // entry sequence.
  const uint64_t exit_address = kEntrySequenceAddress + sizeof(kEntrySequence);
  UNICORN_CHECK(uc_reg_write(uc, UC_ARM64_REG_X30, &exit_address));

  // Execute the entry sequence.
  // For performance reasons, all calls to uc_emu_start should either limit the
  // number of instructions executed or not limit the number of instructions
  // executed. Switching between these modes will flush the code translation
  // buffer in Unicorn v2.
  UNICORN_CHECK(uc_emu_start(uc, kEntrySequenceAddress, exit_address, 0, 0));

  // Unmap the entry sequence
  UNICORN_CHECK(uc_mem_unmap(uc, kEntrySequenceAddress, 0x1000));
}

const size_t kNumUnicornAArch64Reg = 70;

const int kUnicornAArch64RegNames[] = {
    // GP Reg
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
    UC_ARM64_REG_X2,
    UC_ARM64_REG_X3,
    UC_ARM64_REG_X4,
    UC_ARM64_REG_X5,
    UC_ARM64_REG_X6,
    UC_ARM64_REG_X7,
    UC_ARM64_REG_X8,
    UC_ARM64_REG_X9,
    UC_ARM64_REG_X10,
    UC_ARM64_REG_X11,
    UC_ARM64_REG_X12,
    UC_ARM64_REG_X13,
    UC_ARM64_REG_X14,
    UC_ARM64_REG_X15,
    UC_ARM64_REG_X16,
    UC_ARM64_REG_X17,
    UC_ARM64_REG_X18,
    UC_ARM64_REG_X19,
    UC_ARM64_REG_X20,
    UC_ARM64_REG_X21,
    UC_ARM64_REG_X22,
    UC_ARM64_REG_X23,
    UC_ARM64_REG_X24,
    UC_ARM64_REG_X25,
    UC_ARM64_REG_X26,
    UC_ARM64_REG_X27,
    UC_ARM64_REG_X28,
    UC_ARM64_REG_X29,
    UC_ARM64_REG_X30,

    UC_ARM64_REG_SP,
    UC_ARM64_REG_PC,
    UC_ARM64_REG_NZCV,
    UC_ARM64_REG_TPIDR_EL0,
    UC_ARM64_REG_TPIDRRO_EL0,

    // FP Reg
    UC_ARM64_REG_V0,
    UC_ARM64_REG_V1,
    UC_ARM64_REG_V2,
    UC_ARM64_REG_V3,
    UC_ARM64_REG_V4,
    UC_ARM64_REG_V5,
    UC_ARM64_REG_V6,
    UC_ARM64_REG_V7,
    UC_ARM64_REG_V8,
    UC_ARM64_REG_V9,
    UC_ARM64_REG_V10,
    UC_ARM64_REG_V11,
    UC_ARM64_REG_V12,
    UC_ARM64_REG_V13,
    UC_ARM64_REG_V14,
    UC_ARM64_REG_V15,
    UC_ARM64_REG_V16,
    UC_ARM64_REG_V17,
    UC_ARM64_REG_V18,
    UC_ARM64_REG_V19,
    UC_ARM64_REG_V20,
    UC_ARM64_REG_V21,
    UC_ARM64_REG_V22,
    UC_ARM64_REG_V23,
    UC_ARM64_REG_V24,
    UC_ARM64_REG_V25,
    UC_ARM64_REG_V26,
    UC_ARM64_REG_V27,
    UC_ARM64_REG_V28,
    UC_ARM64_REG_V29,
    UC_ARM64_REG_V30,
    UC_ARM64_REG_V31,

    UC_ARM64_REG_FPSR,
    UC_ARM64_REG_FPCR,
};

static_assert(std::size(kUnicornAArch64RegNames) == kNumUnicornAArch64Reg);

std::array<const void *, kNumUnicornAArch64Reg> UnicornAArch64RegValue(
    const UContext<AArch64> &ucontext) {
  const GRegSet<AArch64> &gregs = ucontext.gregs;
  const FPRegSet<AArch64> &fpregs = ucontext.fpregs;

  return {
      // GP Reg
      &gregs.x[0],
      &gregs.x[1],
      &gregs.x[2],
      &gregs.x[3],
      &gregs.x[4],
      &gregs.x[5],
      &gregs.x[6],
      &gregs.x[7],
      &gregs.x[8],
      &gregs.x[9],
      &gregs.x[10],
      &gregs.x[11],
      &gregs.x[12],
      &gregs.x[13],
      &gregs.x[14],
      &gregs.x[15],
      &gregs.x[16],
      &gregs.x[17],
      &gregs.x[18],
      &gregs.x[19],
      &gregs.x[20],
      &gregs.x[21],
      &gregs.x[22],
      &gregs.x[23],
      &gregs.x[24],
      &gregs.x[25],
      &gregs.x[26],
      &gregs.x[27],
      &gregs.x[28],
      &gregs.x[29],
      &gregs.x[30],

      &gregs.sp,
      &gregs.pc,
      &gregs.pstate,
      &gregs.tpidr,
      &gregs.tpidrro,

      // FP Reg
      &fpregs.v[0],
      &fpregs.v[1],
      &fpregs.v[2],
      &fpregs.v[3],
      &fpregs.v[4],
      &fpregs.v[5],
      &fpregs.v[6],
      &fpregs.v[7],
      &fpregs.v[8],
      &fpregs.v[9],
      &fpregs.v[10],
      &fpregs.v[11],
      &fpregs.v[12],
      &fpregs.v[13],
      &fpregs.v[14],
      &fpregs.v[15],
      &fpregs.v[16],
      &fpregs.v[17],
      &fpregs.v[18],
      &fpregs.v[19],
      &fpregs.v[20],
      &fpregs.v[21],
      &fpregs.v[22],
      &fpregs.v[23],
      &fpregs.v[24],
      &fpregs.v[25],
      &fpregs.v[26],
      &fpregs.v[27],
      &fpregs.v[28],
      &fpregs.v[29],
      &fpregs.v[30],
      &fpregs.v[31],

      &fpregs.fpsr,
      &fpregs.fpcr,
  };
}

}  // namespace

template <>
uint64_t UnicornTracer<AArch64>::GetInstructionPointer() {
  uint64_t pc = 0;
  UNICORN_CHECK(uc_reg_read(uc_, UC_ARM64_REG_PC, &pc));
  return pc;
}

template <>
void UnicornTracer<AArch64>::SetInstructionPointer(uint64_t address) {
  UNICORN_CHECK(uc_reg_write(uc_, UC_ARM64_REG_PC, &address));
}

template <>
uint64_t UnicornTracer<AArch64>::GetStackPointer() {
  uint64_t sp = 0;
  UNICORN_CHECK(uc_reg_read(uc_, UC_ARM64_REG_SP, &sp));
  return sp;
}

template <>
void UnicornTracer<AArch64>::InitUnicorn(
    const UnicornTracerConfig<AArch64> &tracer_config) {
  UNICORN_CHECK(uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc_));
  UNICORN_CHECK(uc_ctl_set_cpu_model(
      uc_, tracer_config.force_a72 ? UC_CPU_ARM64_A72 : UC_CPU_ARM64_MAX));
  SetupCPUState(uc_);
}

template <>
void UnicornTracer<AArch64>::SetupSnippetMemory(
    const Snapshot &snapshot, const UContext<AArch64> &ucontext,
    const FuzzingConfig<AArch64> &fuzzing_config) {
  for (const Snapshot::MemoryMapping &mm : snapshot.memory_mappings()) {
    MapMemory(mm.start_address(), mm.num_bytes(),
              MemoryPermsToUnicorn(mm.perms()));
  }

  for (const Snapshot::MemoryBytes &mb : snapshot.memory_bytes()) {
    const Snapshot::ByteData &data = mb.byte_values();
    UNICORN_CHECK(
        uc_mem_write(uc_, mb.start_address(), data.data(), data.size()));
  }

  // These mappings are currently not represented in the Snapshot.
  MapMemory(fuzzing_config.data1_range.start_address,
            fuzzing_config.data1_range.num_bytes, UC_PROT_READ | UC_PROT_WRITE);
  MapMemory(fuzzing_config.data2_range.start_address,
            fuzzing_config.data2_range.num_bytes, UC_PROT_READ | UC_PROT_WRITE);

  // Simulate the effect RestoreUContext could have on the stack.
  std::string stack_bytes = RestoreUContextStackBytes(ucontext.gregs);
  UNICORN_CHECK(
      uc_mem_write(uc_, ucontext.gregs.GetStackPointer() - stack_bytes.size(),
                   stack_bytes.data(), stack_bytes.size()));
}

template <>
void UnicornTracer<AArch64>::GetRegisters(UContext<AArch64> &ucontext) {
  // Not all registers will be read. memset so the result is consistent.
  memset(&ucontext, 0, sizeof(ucontext));
  std::array<const void *, kNumUnicornAArch64Reg> ptrs =
      UnicornAArch64RegValue(ucontext);
  for (size_t i = 0; i < kNumUnicornAArch64Reg; ++i) {
    // It's a bit hackish to cast away the constness of UnicornAArch64RegValue,
    // but it's cleaner than having two const and non-const versions of the
    // function.
    uc_reg_read(uc_, kUnicornAArch64RegNames[i], const_cast<void *>(ptrs[i]));
  }
}

template <>
void UnicornTracer<AArch64>::SetRegisters(const UContext<AArch64> &ucontext) {
  // uc_reg_write_batch appears to work fine for aarch64, but we're writing the
  // registers one by one to match the x86_64 implementation.
  std::array<const void *, kNumUnicornAArch64Reg> ptrs =
      UnicornAArch64RegValue(ucontext);
  for (size_t i = 0; i < kNumUnicornAArch64Reg; ++i) {
    uc_reg_write(uc_, kUnicornAArch64RegNames[i], ptrs[i]);
  }
}

template <>
void UnicornTracer<AArch64>::SetInitialRegisters(
    const UContext<AArch64> &ucontext) {
  SetRegisters(ucontext);
}

template <>
absl::Status UnicornTracer<AArch64>::ValidateArchEndState() {
  // aarch64 requires that stack pointers are 16-byte aligned when they are
  // used. The exit sequence will use the stack pointer, so SP needs to be
  // aligned when the instruction sequence exits.
  // Note that QEMU appears to not care about unaligned stack pointers. Hardware
  // cares, however, and this creates skew between the proxy and hardware.
  // Checking the stack pointer alignment on exit should help filter out some,
  // but not all of these problems. It will not catch situations where the stack
  // pointer is unaligned during execution, but becomes re-aligned before
  // exiting.
  uint64_t sp = GetStackPointer();
  constexpr uint64_t kRequiredStackAlignment = 16;
  if (sp % kRequiredStackAlignment != 0) {
    return absl::InternalError("stack pointer misaligned on exit");
  }

  return absl::OkStatus();
}

}  // namespace silifuzz
