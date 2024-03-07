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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_UCONTEXT_SIGNAL_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_UCONTEXT_SIGNAL_H_

#include <ucontext.h>  // for ucontext_t

#include <cstdint>

#include "absl/base/attributes.h"
#include "./util/arch.h"
#include "./util/ucontext/ucontext_types.h"

#ifdef __x86_64__
#include "./util/ucontext/x86_64/x86_segment_base.h"
#endif

namespace silifuzz {

// Additional general registers that are not part of ucontext_t.
struct ExtraSignalRegs;

// The following functions may be called in a signal handler and the TLS
// pointer is an invalid value. Actual function calls can trigger lazy dynamic
// linking, which requires TLS. TSAN also appears to require TLS. To avoid
// problems, force the inlining of these functions.

// Save registers that were not captured by the signal handler. Must be called
// before RestoreStateInSignalHandler.
ABSL_ATTRIBUTE_ALWAYS_INLINE static inline void SaveExtraSignalRegsNoSyscalls(
    ExtraSignalRegs* extra_gregs);
ABSL_ATTRIBUTE_ALWAYS_INLINE static inline void SaveExtraSignalRegs(
    ExtraSignalRegs* extra_gregs);

// Restore the registers needed for C runtime, dynamic linking, and various
// sanitizers that may have been smashed by a snap but not restored by the
// signal handler. For the most part, this is restoring the TLS register.
ABSL_ATTRIBUTE_ALWAYS_INLINE static inline void RestoreStateInSignalHandler(
    UContext<Host>* uc);

#if defined(__x86_64__)
struct SignalRegSet {
  // The uc_mcontext.gregs[REG_ERR] value in ucontext_t in the signal handler.
  // Describes the reason for signum, when it's SIGSEGV.
  uint64_t err;

  // The uc_mcontext.gregs[REG_CR2] and [REG_TRAPNO] values in ucontext_t in the
  // signal handler.
  // Used only for logging currently: can be part of a signature of an
  // unexpected SIGSEGV.
  uint64_t cr2;
  uint64_t trapno;
};

struct ExtraSignalRegs {
  uint64_t fs_base;
  uint64_t gs_base;
  uint16_t ss;
  uint16_t ds;
  uint16_t es;
};

void SaveExtraSignalRegsNoSyscalls(ExtraSignalRegs* extra_gregs) {
  extra_gregs->fs_base = 0;
  extra_gregs->gs_base = 0;
  asm("movw %%ss, %0" : "=r"(extra_gregs->ss) :);
  asm("movw %%ds, %0" : "=r"(extra_gregs->ds) :);
  asm("movw %%es, %0" : "=r"(extra_gregs->es) :);
}

void SaveExtraSignalRegs(ExtraSignalRegs* extra_gregs) {
  extra_gregs->fs_base = GetFSBase();
  extra_gregs->gs_base = GetGSBase();
  asm("movw %%ss, %0" : "=r"(extra_gregs->ss) :);
  asm("movw %%ds, %0" : "=r"(extra_gregs->ds) :);
  asm("movw %%es, %0" : "=r"(extra_gregs->es) :);
}

void RestoreStateInSignalHandler(UContext<X86_64>* uc) {
  SetFSBase(uc->gregs.fs_base);
  SetGSBase(uc->gregs.gs_base);
}
#elif defined(__aarch64__)
struct SignalRegSet {
  // The Exception Syndrome Register. Packed bits containing information about
  // the exception that cause this signal.
  // See:
  // https://developer.arm.com/documentation/ddi0595/2020-12/AArch64-Registers/ESR-EL1--Exception-Syndrome-Register--EL1-
  uint64_t esr;
};

struct ExtraSignalRegs {
  uint64_t tpidr;
  uint64_t tpidrro;
};

void SaveExtraSignalRegsNoSyscalls(ExtraSignalRegs* extra_gregs) {
  asm("mrs %0, tpidr_el0" : "=r"(extra_gregs->tpidr) :);
  asm("mrs %0, tpidrro_el0" : "=r"(extra_gregs->tpidrro) :);
}

void SaveExtraSignalRegs(ExtraSignalRegs* extra_gregs) {
  SaveExtraSignalRegsNoSyscalls(extra_gregs);
}

#else
#error "Unsupported architecture"
#endif

// Convert the general registers from libc's ucontext_t to the type in UContext.
// The extra_gregs contain registers that are not provided by the kernel to the
// signal handler as a part of ucontext_t/sigcontext interface.
// Is async-signal-safe.
// CAVEAT: In a multithreaded process "the kernel chooses an arbitrary thread to
// which to deliver the signal". We assume both libc_ucontext and extra_gregs
// captured by SaveExtraSignalRegs() will belong to the same thread when passed
// to ConvertGRegsFromLibC(). If not, we'll be creating a snapshot with a
// register state that does not correspond to any thread in the current process.
void ConvertGRegsFromLibC(const ucontext_t& libc_ucontext,
                          const ExtraSignalRegs& extra_gregs,
                          GRegSet<Host>* gregs);

// Convert the FP registers from libc's ucontext_t to the type in UContext.
// Is async-signal-safe.
void ConvertFPRegsFromLibC(const ucontext_t& libc_ucontext,
                           FPRegSet<Host>* fpregs);

// Convert the registers that accompany a signal from libc's ucontext_t to an
// internal data structure.
void ConvertSignalRegsFromLibC(const ucontext_t& libc_ucontext,
                               SignalRegSet* sigregs);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_UCONTEXT_SIGNAL_H_
