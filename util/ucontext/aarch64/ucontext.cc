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

namespace silifuzz {

#define FIELD_SZ(ty, fld) sizeof(((ty*)0)->fld)

static_assert((FIELD_SZ(GRegSet<AArch64>, x) + FIELD_SZ(GRegSet<AArch64>, sp) +
               FIELD_SZ(GRegSet<AArch64>, pc) +
               FIELD_SZ(GRegSet<AArch64>, pstate) +
               FIELD_SZ(GRegSet<AArch64>, tpidr) +
               FIELD_SZ(GRegSet<AArch64>, tpidrro)) == sizeof(GRegSet<AArch64>),
              "Struct should not have invisible padding.");

static_assert((FIELD_SZ(FPRegSet<AArch64>, v) +
               FIELD_SZ(FPRegSet<AArch64>, fpsr) +
               FIELD_SZ(FPRegSet<AArch64>, fpcr)) == sizeof(FPRegSet<AArch64>),
              "Struct should not have invisible padding.");

#undef FIELD_SZ

template <>
void FixUpGRegsPadding(GRegSet<AArch64>* gregs) {}

template <>
void FixUpFPRegsPadding(FPRegSet<AArch64>* fpregs) {}

template <>
void ZeroOutFPRegsPadding(FPRegSet<AArch64>* fpregs) {
  FixUpFPRegsPadding(fpregs);
#if defined(MEMORY_SANITIZER)
  __msan_unpoison(fpregs, sizeof(*fpregs));
#endif
}

template <>
void ZeroOutGRegsPadding(GRegSet<AArch64>* gregs) {
  FixUpGRegsPadding(gregs);
#if defined(MEMORY_SANITIZER)
  __msan_unpoison(gregs, sizeof(*gregs));
#endif
}

template <>
bool CriticalUnrestoredRegistersAreSame(const GRegSet<AArch64>& actual,
                                        const GRegSet<AArch64>& expected) {
  return true;
}

template <>
uint64_t GetInstructionPointer(const GRegSet<AArch64>& gregs) {
  return gregs.pc;
}

}  // namespace silifuzz
