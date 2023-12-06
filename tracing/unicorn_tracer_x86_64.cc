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
#include "third_party/unicorn/unicorn.h"
#include "third_party/unicorn/x86.h"

namespace silifuzz {

namespace {

const size_t kNumUnicornX86_64Reg = 56;

const int kUnicornX86_64RegNames[] = {
    // GP Reg
    UC_X86_REG_R8,
    UC_X86_REG_R9,
    UC_X86_REG_R10,
    UC_X86_REG_R11,
    UC_X86_REG_R12,
    UC_X86_REG_R13,
    UC_X86_REG_R14,
    UC_X86_REG_R15,
    UC_X86_REG_RDI,
    UC_X86_REG_RSI,
    UC_X86_REG_RBP,
    UC_X86_REG_RBX,
    UC_X86_REG_RDX,
    UC_X86_REG_RAX,
    UC_X86_REG_RCX,

    UC_X86_REG_RSP,
    UC_X86_REG_RIP,
    UC_X86_REG_EFLAGS,

    UC_X86_REG_CS,
    UC_X86_REG_ES,
    UC_X86_REG_DS,
    UC_X86_REG_FS,
    UC_X86_REG_GS,
    UC_X86_REG_SS,

    UC_X86_REG_FS_BASE,
    UC_X86_REG_GS_BASE,

    // FP Reg
    UC_X86_REG_FPCW,
    UC_X86_REG_FPSW,

    // missing: ftw
    // Unicorn technically has UC_X86_REG_FPTAG, but this is a 16-bit value.
    // FTW from fxsave is an abridged 8-bit version. Skipping for now.
    // TODO(ncbray): pack/unpack abridged tag word.

    UC_X86_REG_FOP,
    UC_X86_REG_FIP,
    UC_X86_REG_FDP,

    UC_X86_REG_MXCSR,

    // missing: mxcsr_mask

    UC_X86_REG_ST0,
    UC_X86_REG_ST1,
    UC_X86_REG_ST2,
    UC_X86_REG_ST3,
    UC_X86_REG_ST4,
    UC_X86_REG_ST5,
    UC_X86_REG_ST6,
    UC_X86_REG_ST7,

    UC_X86_REG_XMM0,
    UC_X86_REG_XMM1,
    UC_X86_REG_XMM2,
    UC_X86_REG_XMM3,
    UC_X86_REG_XMM4,
    UC_X86_REG_XMM5,
    UC_X86_REG_XMM6,
    UC_X86_REG_XMM7,
    UC_X86_REG_XMM8,
    UC_X86_REG_XMM9,
    UC_X86_REG_XMM10,
    UC_X86_REG_XMM11,
    UC_X86_REG_XMM12,
    UC_X86_REG_XMM13,
    UC_X86_REG_XMM14,
    UC_X86_REG_XMM15,
};

static_assert(std::size(kUnicornX86_64RegNames) == kNumUnicornX86_64Reg);

std::array<const void *, kNumUnicornX86_64Reg> UnicornX86_64RegValue(
    const UContext<X86_64> &ucontext) {
  const GRegSet<X86_64> &gregs = ucontext.gregs;
  const FPRegSet<X86_64> &fpregs = ucontext.fpregs;

  return {
      // GP Reg
      &gregs.r8,
      &gregs.r9,
      &gregs.r10,
      &gregs.r11,
      &gregs.r12,
      &gregs.r13,
      &gregs.r14,
      &gregs.r15,
      &gregs.rdi,
      &gregs.rsi,
      &gregs.rbp,
      &gregs.rbx,
      &gregs.rdx,
      &gregs.rax,
      &gregs.rcx,
      &gregs.rsp,
      &gregs.rip,
      &gregs.eflags,

      &gregs.cs,
      &gregs.es,
      &gregs.ds,
      &gregs.fs,
      &gregs.gs,
      &gregs.ss,

      &gregs.fs_base,
      &gregs.gs_base,

      // FP Reg
      &fpregs.fcw,
      &fpregs.fsw,

      &fpregs.fop,
      &fpregs.rip,
      &fpregs.rdp,

      &fpregs.mxcsr,

      &fpregs.st[0],
      &fpregs.st[1],
      &fpregs.st[2],
      &fpregs.st[3],
      &fpregs.st[4],
      &fpregs.st[5],
      &fpregs.st[6],
      &fpregs.st[7],

      &fpregs.xmm[0],
      &fpregs.xmm[1],
      &fpregs.xmm[2],
      &fpregs.xmm[3],
      &fpregs.xmm[4],
      &fpregs.xmm[5],
      &fpregs.xmm[6],
      &fpregs.xmm[7],
      &fpregs.xmm[8],
      &fpregs.xmm[9],
      &fpregs.xmm[10],
      &fpregs.xmm[11],
      &fpregs.xmm[12],
      &fpregs.xmm[13],
      &fpregs.xmm[14],
      &fpregs.xmm[15],
  };
}

}  // namespace

template <>
uint64_t UnicornTracer<X86_64>::GetCurrentInstructionPointer() {
  uint64_t pc = 0;
  UNICORN_CHECK(uc_reg_read(uc_, UC_X86_REG_RIP, &pc));
  return pc;
}

template <>
void UnicornTracer<X86_64>::SetCurrentInstructionPointer(uint64_t address) {
  UNICORN_CHECK(uc_reg_write(uc_, UC_X86_REG_RIP, &address));
}

template <>
uint64_t UnicornTracer<X86_64>::GetCurrentStackPointer() {
  uint64_t sp = 0;
  UNICORN_CHECK(uc_reg_read(uc_, UC_X86_REG_RSP, &sp));
  return sp;
}

template <>
void UnicornTracer<X86_64>::InitUnicorn() {
  UNICORN_CHECK(uc_open(UC_ARCH_X86, UC_MODE_64, &uc_));

  // TODO(ncbray): remove #if when transition is complete.
#if UC_API_MAJOR >= 2
  // TODO(ncbray): make this configurable.
  UNICORN_CHECK(uc_ctl_set_cpu_model(uc_, UC_CPU_X86_CASCADELAKE_SERVER));
#endif

  // Set OSFXSR bit in CR4 to enable FXSAVE and FXRSTOR handling of XMM
  // registers. See https://en.wikipedia.org/wiki/Control_register#CR4
  uint64_t cr4 = 0;
  UNICORN_CHECK(uc_reg_read(uc_, UC_X86_REG_CR4, &cr4));
  cr4 |= (1ULL << 9);
  UNICORN_CHECK(uc_reg_write(uc_, UC_X86_REG_CR4, &cr4));
}

template <>
void UnicornTracer<X86_64>::SetupSnippetMemory(
    const Snapshot &snapshot, const UContext<X86_64> &ucontext,
    const FuzzingConfig<X86_64> &fuzzing_config) {
  for (const Snapshot::MemoryMapping &mm : snapshot.memory_mappings()) {
    // The stack is aliased with data1, and Unicorn doesn't like mapping the
    // same memory twice. Hack around this by skipping RW mappings.
    if (mm.perms() == MemoryPerms::RW()) continue;
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
void UnicornTracer<X86_64>::GetRegisters(UContext<X86_64> &ucontext) {
  // Not all registers will be read. Unicorn also does not set the upper bits of
  // st registers. memset so the result is consistent.
  memset(&ucontext, 0, sizeof(ucontext));
  std::array<const void *, kNumUnicornX86_64Reg> ptrs =
      UnicornX86_64RegValue(ucontext);
  for (size_t i = 0; i < kNumUnicornX86_64Reg; ++i) {
    // It's a bit hackish to cast away the constness of UnicornX86_64RegValue,
    // but it's cleaner than having two const and non-const versions of the
    // function.
    uc_reg_read(uc_, kUnicornX86_64RegNames[i], const_cast<void *>(ptrs[i]));
  }
}

template <>
void UnicornTracer<X86_64>::SetRegisters(const UContext<X86_64> &ucontext) {
  // uc_reg_write_batch does not seem to set all of the registers correctly,
  // (the higher XMM registers for example) but individual uc_reg_write calls
  // seem to work fine.
  std::array<const void *, kNumUnicornX86_64Reg> ptrs =
      UnicornX86_64RegValue(ucontext);
  for (size_t i = 0; i < kNumUnicornX86_64Reg; ++i) {
    uc_reg_write(uc_, kUnicornX86_64RegNames[i], ptrs[i]);
  }
}

template <>
void UnicornTracer<X86_64>::SetInitialRegisters(
    const UContext<X86_64> &ucontext) {
  const FPRegSet<X86_64> &fpregs = ucontext.fpregs;

  constexpr size_t kFPRegsSize = sizeof(fpregs);
  static_assert(kFPRegsSize == 512,
                "FPRegSet must be as expected by FXRSTOR64");

  // Restore fpregs state by copying fpregs contents into the emulator's
  // address space and executing FXRSTOR64. It's not otherwise possible to
  // restore all FP registers using uc_reg_write* APIs.
  //
  // Use page 0 to stage the fpregs and the restore code.
  const uint64_t addr = 0;
  UNICORN_CHECK(uc_reg_write(uc_, UC_X86_REG_RDI, &addr));
  UNICORN_CHECK(uc_mem_map(uc_, addr, kPageSize, UC_PROT_ALL));
  UNICORN_CHECK(uc_mem_write(uc_, addr, &fpregs, kFPRegsSize));
  // fxrstor64 [rdi]
  const std::string fxRstorRdiByteCode = {0x48, 0x0F, 0xAE, 0x0F};
  const uint64_t code_begin = addr + kFPRegsSize;
  const uint64_t code_end = code_begin + fxRstorRdiByteCode.length();
  UNICORN_CHECK(uc_mem_write(uc_, code_begin, fxRstorRdiByteCode.data(),
                             fxRstorRdiByteCode.length()));
  // For performance reasons, all calls to uc_emu_start should either limit the
  // number of instructions executed or not limit the number of instructions
  // executed. Switching between these modes will flush the code translation
  // buffer in Unicorn v2.
  UNICORN_CHECK(uc_emu_start(uc_, code_begin, code_end, 0, 0));
  UNICORN_CHECK(uc_mem_unmap(uc_, addr, kPageSize));

  // This will redundantly set some of the floating point registers, but that
  // keeps the code simpler.
  SetRegisters(ucontext);
}

template <>
absl::Status UnicornTracer<X86_64>::ValidateArchEndState() {
  // No additional checks needed.
  return absl::OkStatus();
}

}  // namespace silifuzz
