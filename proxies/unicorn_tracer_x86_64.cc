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

#include <cstddef>
#include <cstdint>

#include "absl/status/status.h"
#include "./common/proxy_config.h"
#include "./common/snapshot.h"
#include "./proxies/unicorn_tracer.h"
#include "./proxies/unicorn_util.h"
#include "./util/arch.h"
#include "./util/arch_mem.h"
#include "./util/page_util.h"
#include "./util/ucontext/ucontext.h"
#include "third_party/unicorn/unicorn.h"

namespace silifuzz {

template <>
uint64_t UnicornTracer<X86_64>::GetCurrentInstructionPointer() {
  uint64_t pc = 0;
  UNICORN_CHECK(uc_reg_read(uc_, UC_X86_REG_RIP, &pc));
  return pc;
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
    MapMemory(uc_, mm.start_address(), mm.num_bytes(), mm.perms());
  }

  for (const Snapshot::MemoryBytes &mb : snapshot.memory_bytes()) {
    const Snapshot::ByteData &data = mb.byte_values();
    UNICORN_CHECK(
        uc_mem_write(uc_, mb.start_address(), data.data(), data.size()));
  }

  // These mappings are currently not represented in the Snapshot.
  MapMemory(uc_, fuzzing_config.data1_range.start_address,
            fuzzing_config.data1_range.num_bytes, UC_PROT_READ | UC_PROT_WRITE);
  MapMemory(uc_, fuzzing_config.data2_range.start_address,
            fuzzing_config.data2_range.num_bytes, UC_PROT_READ | UC_PROT_WRITE);

  // Simulate the effect RestoreUContext could have on the stack.
  std::string stack_bytes = RestoreUContextStackBytes(ucontext.gregs);
  UNICORN_CHECK(
      uc_mem_write(uc_, GetStackPointer(ucontext.gregs) - stack_bytes.size(),
                   stack_bytes.data(), stack_bytes.size()));
}

template <>
void UnicornTracer<X86_64>::SetInitialRegisters(
    const UContext<X86_64> &ucontext) {
  const GRegSet<X86_64> &gregs = ucontext.gregs;
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
  UNICORN_CHECK(uc_mem_write(uc_, addr + kFPRegsSize, fxRstorRdiByteCode.data(),
                             fxRstorRdiByteCode.length()));
  // Execute exactly one instruction (count=1).
  UNICORN_CHECK(uc_emu_start(uc_, addr + kFPRegsSize, 0, 0, /* count = */ 1));
  UNICORN_CHECK(uc_mem_unmap(uc_, addr, kPageSize));

  // List of all general purpose registers to write to Unicorn.
  // uc_reg_write_batch() is smart enough to distinguish the sizes of
  // underlying registers (e.g. 64 bit %RAX vs 32 bit %SS).
  int kX86UnicornGregs[] = {
      UC_X86_REG_RAX,     UC_X86_REG_RBX,    UC_X86_REG_RCX, UC_X86_REG_RDX,
      UC_X86_REG_RSP,     UC_X86_REG_RBP,    UC_X86_REG_RDI, UC_X86_REG_RSI,
      UC_X86_REG_RIP,     UC_X86_REG_EFLAGS, UC_X86_REG_R8,  UC_X86_REG_R9,
      UC_X86_REG_R10,     UC_X86_REG_R11,    UC_X86_REG_R12, UC_X86_REG_R13,
      UC_X86_REG_R14,     UC_X86_REG_R15,    UC_X86_REG_CS,  UC_X86_REG_ES,
      UC_X86_REG_DS,      UC_X86_REG_FS,     UC_X86_REG_GS,  UC_X86_REG_SS,
      UC_X86_REG_FS_BASE, UC_X86_REG_GS_BASE};

  const void *gregs_srs[] = {
      &gregs.rax,    &gregs.rbx, &gregs.rcx, &gregs.rdx, &gregs.rsp,
      &gregs.rbp,    &gregs.rdi, &gregs.rsi, &gregs.rip, &gregs.eflags,
      &gregs.r8,     &gregs.r9,  &gregs.r10, &gregs.r11, &gregs.r12,
      &gregs.r13,    &gregs.r14, &gregs.r15, &gregs.cs,  &gregs.es,
      &gregs.ds,     &gregs.fs,  &gregs.gs,  &gregs.ss,  &gregs.fs_base,
      &gregs.gs_base};
  static_assert(ABSL_ARRAYSIZE(gregs_srs) == ABSL_ARRAYSIZE(kX86UnicornGregs));

  // uc_reg_write_batch wants vals of type (void* const*) which is an
  // "array of const pointer to void" but it should have been "array of pointer
  // to const void" (i.e. the value under the pointer cannot change). Therefore
  // the cast.
  UNICORN_CHECK(
      uc_reg_write_batch(uc_,
                         /* regs = */ kX86UnicornGregs,
                         /* vals = */ const_cast<void *const *>(gregs_srs),
                         ABSL_ARRAYSIZE(gregs_srs)));
}

template <>
absl::Status UnicornTracer<X86_64>::ValidateArchEndState() {
  // No additional checks needed.
  return absl::OkStatus();
}

}  // namespace silifuzz
