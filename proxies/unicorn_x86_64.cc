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

#include "./proxies/unicorn_x86_64.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>

#include "absl/base/macros.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "./common/raw_insns_util.h"
#include "./common/snapshot_util.h"
#include "./util/checks.h"
#include "./util/ucontext/ucontext_types.h"
#include "third_party/unicorn/unicorn.h"
#include "third_party/unicorn/x86.h"

namespace {

using silifuzz::FPRegSet;
using silifuzz::GRegSet;
using silifuzz::X86_64;

absl::StatusOr<uc_err> Initialize(uc_engine *uc, const GRegSet<X86_64> &gregs,
                                  const FPRegSet<X86_64> &fpregs) {
  // Set OSFXSR bit in CR4 to enable FXSAVE and FXRSTOR handling of XMM
  // registers. See https://en.wikipedia.org/wiki/Control_register#CR4
  uint64_t cr4 = 0;
  UNICORN_RETURN_IF_NOT_OK(uc_reg_read(uc, UC_X86_REG_CR4, &cr4));
  cr4 |= (1ULL << 9);
  UNICORN_RETURN_IF_NOT_OK(uc_reg_write(uc, UC_X86_REG_CR4, &cr4));

  constexpr size_t kFPRegsSize = sizeof(fpregs);
  static_assert(kFPRegsSize == 512,
                "FPRegSet must be as expected by FXRSTOR64");

  // Restore fpregs state by copying fpregs contents into the emulator's
  // address space and executing FXRSTOR64. It's not otherwise possible to
  // restore all FP registers using uc_reg_write* APIs.
  //
  // Use page 0 to stage the fpregs and the restore code.
  uint64_t addr = 0;
  UNICORN_RETURN_IF_NOT_OK(uc_reg_write(uc, UC_X86_REG_RDI, &addr));
  UNICORN_RETURN_IF_NOT_OK(uc_mem_map(uc, addr, kPageSize, UC_PROT_ALL));
  UNICORN_RETURN_IF_NOT_OK(uc_mem_write(uc, addr, &fpregs, kFPRegsSize));
  // fxrstor64 [rdi]
  const std::string fxRstorRdiByteCode = {0x48, 0x0F, 0xAE, 0x0F};
  UNICORN_RETURN_IF_NOT_OK(uc_mem_write(uc, addr + kFPRegsSize,
                                        fxRstorRdiByteCode.data(),
                                        fxRstorRdiByteCode.length()));
  // Execute exactly one instruction (count=1).
  UNICORN_RETURN_IF_NOT_OK(
      uc_emu_start(uc, addr + kFPRegsSize, 0, 0, /* count = */ 1));
  UNICORN_RETURN_IF_NOT_OK(uc_mem_unmap(uc, addr, kPageSize));

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
  UNICORN_RETURN_IF_NOT_OK(
      uc_reg_write_batch(uc,
                         /* regs = */ kX86UnicornGregs,
                         /* vals = */ const_cast<void *const *>(gregs_srs),
                         ABSL_ARRAYSIZE(gregs_srs)));
  return UC_ERR_OK;
}

}  // namespace

namespace silifuzz {

absl::StatusOr<uc_err> RunInstructions(absl::string_view insns) {
  ASSIGN_OR_RETURN_IF_NOT_OK(
      Snapshot snapshot,
      InstructionsToSnapshot_X86_64(insns, kCodeAddr, kCodeLimit - kCodeAddr,
                                    kMem1Addr));
  const uint64_t code_addr = snapshot.ExtractRip(snapshot.registers());
  const Snapshot::MemoryBytes *code_bytes = [&]() {
    for (const Snapshot::MemoryBytes &mb : snapshot.memory_bytes()) {
      if (mb.start_address() == code_addr) {
        return &mb;
      }
    }
    LOG_FATAL("Code page not found");
  }();

  // Initialize emulator, ensure uc_close() is called on return.
  uc_engine *uc;
  ScopedUC scoped_uc(UC_ARCH_X86, UC_MODE_64, &uc);

  // Set registers.
  GRegSet<X86_64> gregs;
  FPRegSet<X86_64> fpregs;
  RETURN_IF_NOT_OK(
      ConvertRegsFromSnapshot(snapshot.registers(), &gregs, &fpregs));

  RETURN_IF_NOT_OK(Initialize(uc, gregs, fpregs).status());

  // Map the code page.
  UNICORN_RETURN_IF_NOT_OK(uc_mem_map(uc, code_bytes->start_address(),
                                      code_bytes->num_bytes(), UC_PROT_EXEC));
  UNICORN_RETURN_IF_NOT_OK(uc_mem_write(uc, code_bytes->start_address(),
                                        code_bytes->byte_values().data(),
                                        code_bytes->num_bytes()));

  // Map the data region(s).
  UNICORN_RETURN_IF_NOT_OK(uc_mem_map(uc, kMem1Addr, kMem1Limit - kMem1Addr,
                                      UC_PROT_READ | UC_PROT_WRITE));
  UNICORN_RETURN_IF_NOT_OK(uc_mem_map(uc, kMem2Addr, kMem2Limit - kMem2Addr,
                                      UC_PROT_READ | UC_PROT_WRITE));

  // Emulate up to kMaxInstExecuted instructions.
  uint64_t end_of_code = code_addr + insns.size();
  size_t kMaxInstExecuted = 100;
  UNICORN_RETURN_IF_NOT_OK(
      uc_emu_start(uc, code_addr, end_of_code, 0, kMaxInstExecuted));

  // Reject the input if emulation didn't finish at end_of_code.
  uint64_t pc = 0;
  UNICORN_RETURN_IF_NOT_OK(uc_reg_read(uc, UC_X86_REG_RIP, &pc));
  if (pc != end_of_code) {
    return absl::OutOfRangeError("Didn't reach expected PC");
  }

  // Accept the input.
  return UC_ERR_OK;
}

}  // namespace silifuzz
