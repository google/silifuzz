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

#include "./util/checks.h"
#include "./util/ucontext/ucontext.h"

namespace silifuzz {

void ConvertGRegsFromLibC(const ucontext_t& libc_ucontext,
                          const ExtraSignalRegs& extra_gregs, GRegSet* gregs) {
  auto& mcontext = libc_ucontext.uc_mcontext;

  // Copy the part of ucontext_t::mcontext.gregs that has the same layout
  // as GRegSet:
  memcpy(gregs, &mcontext.gregs, offsetof(GRegSet, ss));
  gregs->ss = extra_gregs.ss;
  gregs->ds = extra_gregs.ds;
  gregs->es = extra_gregs.es;
  gregs->fs_base = extra_gregs.fs_base;
  gregs->gs_base = extra_gregs.gs_base;
  ZeroOutGRegsPadding(gregs);
}

// TODO(ksteuck): [as-needed] This is called when libc_ucontext was made by
// a signal handler. If signal invocation does not use fxsave to save complete
// state of FP regs, we might need to do that ourselves here.
void ConvertFPRegsFromLibC(const ucontext_t& libc_ucontext, FPRegSet* fpregs) {
  auto& mcontext = libc_ucontext.uc_mcontext;

  static_assert(sizeof(*mcontext.fpregs) == sizeof(*fpregs),
                "FP regs type mismatch");

  if (mcontext.fpregs != nullptr) {
    memcpy(fpregs, mcontext.fpregs, sizeof(*fpregs));
    ZeroOutFPRegsPadding(fpregs);
  } else {
    ASS_LOG_FATAL("ucontext_t does not have fpregs");
  }
}

void ConvertSignalRegsFromLibC(const ucontext_t& libc_ucontext,
                               SignalRegSet* sigregs) {
  sigregs->err = libc_ucontext.uc_mcontext.gregs[REG_ERR];
  sigregs->cr2 = libc_ucontext.uc_mcontext.gregs[REG_CR2];
  sigregs->trapno = libc_ucontext.uc_mcontext.gregs[REG_TRAPNO];
}

}  // namespace silifuzz
