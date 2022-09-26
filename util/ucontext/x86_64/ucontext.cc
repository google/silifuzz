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

#include "./util/ucontext/ucontext.h"

#ifdef MEMORY_SANITIZER
#include <sanitizer/msan_interface.h>
#endif

#include <cstddef>

namespace silifuzz {

template <>
void FixUpGRegsPadding(GRegSet<X86_64>* gregs) {
  // TODO(ksteuck): [as-needed] Bits 1, 3, 5, 15, and [22..31] (0-based) of
  // gregs->eflags are documented as reserved and "do not use or depend on"
  // -- see section 3.4.3 in
  // https://www.intel.la/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-1-manual.pdf
  // Hence we might need to clear them here like this if we start seeing
  // discrepancies in the values of those bits. Might need to also clear
  // the same bits in the snapshots of our current corpus(es).
#if 0
  constexpr uint32_t eflags_mask = (1 << 1) | (1 << 3) | (1 << 5) | (1 << 15) |
                                (1 << 22) | (1 << 23) | (1 << 24) | (1 << 25) |
                                (1 << 26) | (1 << 27) | (1 << 28) | (1 << 29) |
                                (1 << 30) | (1 << 31);
  gregs->eflags &= ~eflags_mask;
#endif
}

template <>
void FixUpFPRegsPadding(FPRegSet<X86_64>* fpregs) {
  // According to docs only 16 lower bits of mxcsr have been defined as of SSE3
  // (and hence only that many bits of mxcsr_mask are meaningful)
  // -- see page 10-4 in
  // https://www.intel.la/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-1-manual.pdf
  // But for some reason the 18th bit of mxcsr_mask *sometimes* gets set.
  // This might have to do with the fact that memory is not 0-ed before doing
  // the fxsave64 instruction. We can implement the clearing in
  // ./save_ucontext.S, but then there's similar logic inside Linux kernel
  // when it populates ucontext_t for a signal handler and that logic would be
  // non-trivial to change.
  // As an immediate fix we simply always clear the offending bit to achive
  // consistent mxcsr_mask values for FPRegSet comparisons:
  // TODO(ksteuck): [as-needed] Clear more/all of top two bytes of mxcsr_mask.
  fpregs->mxcsr_mask &= ~0x20000;
}

template <>
void ZeroOutGRegsPadding(GRegSet<X86_64>* gregs) {
  // This padding is to size GRegSet as a multiple of int64_t.
  gregs->padding = 0;
  FixUpGRegsPadding(gregs);
#if defined(MEMORY_SANITIZER)
  // Since MSAN does not understand what the assembly in SaveUContext() does,
  // it does not know what is no longer uninitialized in UContext after
  // SaveUContext() runs. Thus we help MSAN here.
  // Note that if SaveUContext() is not called toghether with
  // ZeroOutRegsPadding() the following can hide some uninitialized usage
  // from MSAN.
  __msan_unpoison(gregs, sizeof(*gregs));
#endif
}

template <>
void ZeroOutFPRegsPadding(FPRegSet<X86_64>* fpregs) {
  fpregs->reserved0 = 0;
  memset(fpregs->padding, 0, sizeof(fpregs->padding));
  FixUpFPRegsPadding(fpregs);

#if defined(MEMORY_SANITIZER)
  __msan_unpoison(fpregs, sizeof(*fpregs));
#endif
}

// Restoring CS and SS is tricky, so RestoreUContext does not do it.
// If they have been modified, then jumping back into C code is unsafe.
// For the nolibc use case, fs_base and gs_base will get zeroed when restoring
// the context, but they are also not used by nolibc C code so they are not
// critical.
template <>
bool CriticalUnrestoredRegistersAreSame(const GRegSet<X86_64>& actual,
                                        const GRegSet<X86_64>& expected) {
  return actual.cs == expected.cs && actual.ss == expected.ss;
}

template <>
uint64_t GetInstructionPointer(const GRegSet<X86_64>& gregs) {
  return gregs.rip;
}

template <>
uint64_t GetStackPointer(const GRegSet<X86_64>& gregs) {
  return gregs.rsp;
}

}  // namespace silifuzz
