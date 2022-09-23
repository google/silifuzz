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

#include "./util/ucontext/signal.h"

#include <signal.h>

#include "absl/base/macros.h"
#include "./util/checks.h"
#include "./util/ucontext/ucontext.h"

namespace silifuzz {

void ConvertGRegsFromLibC(const ucontext_t& libc_ucontext,
                          const ExtraSignalRegs& extra_gregs,
                          GRegSet<AArch64>* gregs) {
  const mcontext_t& mcontext = libc_ucontext.uc_mcontext;

  static_assert(ABSL_ARRAYSIZE(gregs->x) == ABSL_ARRAYSIZE(mcontext.regs),
                "Register array sizes do not match.");

  for (int i = 0; i < ABSL_ARRAYSIZE(gregs->x); ++i) {
    gregs->x[i] = mcontext.regs[i];
  }
  gregs->sp = mcontext.sp;
  gregs->pc = mcontext.pc;
  gregs->pstate = mcontext.pstate;

  gregs->tpidr = extra_gregs.tpidr;
  gregs->tpidrro = extra_gregs.tpidrro;

  ZeroOutGRegsPadding(gregs);
}

// On aarch64 the context structure contains a 4kB "__reserved" field that can
// contain a small variety of data structures that extend the base context.
// This function searches for a specific data structure in the __reserved field.
// See:
// https://github.com/torvalds/linux/blob/master/arch/arm64/include/uapi/asm/sigcontext.h
static const void* FindContext(const ucontext_t& libc_ucontext,
                               uint32_t magic) {
  // Note: we're iterating through the entire structure to prove we understand
  // the structure. An early out would improve performance if it matters.
  const uint8_t* current =
      reinterpret_cast<const uint8_t*>(libc_ucontext.uc_mcontext.__reserved);
  const uint8_t* end = current + sizeof(libc_ucontext.uc_mcontext.__reserved);
  const void* ctx = nullptr;

  while (current < end) {
    const _aarch64_ctx* head = reinterpret_cast<const _aarch64_ctx*>(current);
    if (sizeof(*head) > end - current) {
      ASS_LOG_FATAL("Not enough space for header.");
    }
    if (head->size > end - current) {
      ASS_LOG_FATAL("Not enough space for body.");
    }
    if (head->magic == magic) {
      if (ctx != nullptr) {
        ASS_LOG_FATAL("Found two contexts with the same magic.");
      }
      ctx = current;
    } else if (head->magic == 0) {
      // No more records.
      break;
    }
    // Advance to next.
    current += head->size;
  }

  return ctx;
}

void ConvertFPRegsFromLibC(const ucontext_t& libc_ucontext,
                           FPRegSet<AArch64>* fpregs) {
  const fpsimd_context* fpc = reinterpret_cast<const fpsimd_context*>(
      FindContext(libc_ucontext, FPSIMD_MAGIC));

  if (fpc == nullptr) {
    ASS_LOG_FATAL("Did not find FPSIMD record");
  }

  if (fpc->head.size != sizeof(*fpc)) {
    ASS_LOG_FATAL("FPSIMD record is wrong size.");
  }

  static_assert(ABSL_ARRAYSIZE(fpregs->v) == ABSL_ARRAYSIZE(fpc->vregs),
                "Register array sizes do not match.");

  // Copy the data over.
  for (int i = 0; i < ABSL_ARRAYSIZE(fpregs->v); ++i) {
    fpregs->v[i] = fpc->vregs[i];
  }
  fpregs->fpsr = fpc->fpsr;
  fpregs->fpcr = fpc->fpcr;

  ZeroOutFPRegsPadding(fpregs);
}

void ConvertSignalRegsFromLibC(const ucontext_t& libc_ucontext,
                               SignalRegSet* sigregs) {
  const esr_context* esr_ctx = reinterpret_cast<const esr_context*>(
      FindContext(libc_ucontext, ESR_MAGIC));

  if (esr_ctx != nullptr) {
    if (esr_ctx->head.size != sizeof(*esr_ctx)) {
      ASS_LOG_FATAL("ESR record is wrong size.");
    }
    sigregs->esr = esr_ctx->esr;
  } else {
    // ESR will not always be provided, for example on SIGILL.
    sigregs->esr = 0;
  }
}

}  // namespace silifuzz
