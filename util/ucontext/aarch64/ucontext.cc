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

static_assert((FIELD_SZ(GRegSet, x) + FIELD_SZ(GRegSet, sp) +
               FIELD_SZ(GRegSet, pc) + FIELD_SZ(GRegSet, pstate) +
               FIELD_SZ(GRegSet, tpidr) + FIELD_SZ(GRegSet, tpidrro)) ==
                  sizeof(GRegSet),
              "Struct should not have invisible padding.");

static_assert((FIELD_SZ(FPRegSet, v) + FIELD_SZ(FPRegSet, fpsr) +
               FIELD_SZ(FPRegSet, fpcr)) == sizeof(FPRegSet),
              "Struct should not have invisible padding.");

#undef FIELD_SZ

void ZeroOutFPRegsPadding(FPRegSet* fpregs) {
  FixUpFPRegsPadding(fpregs);
#if defined(MEMORY_SANITIZER)
  __msan_unpoison(fpregs, sizeof(*fpregs));
#endif
}

void ZeroOutGRegsPadding(GRegSet* gregs) {
  FixUpGRegsPadding(gregs);
#if defined(MEMORY_SANITIZER)
  __msan_unpoison(gregs, sizeof(*gregs));
#endif
}

void FixUpGRegsPadding(GRegSet* gregs) {}

void FixUpFPRegsPadding(FPRegSet* fpregs) {}

bool CriticalUnrestoredRegistersAreSame(const GRegSet& actual,
                                        const GRegSet& expected) {
  return true;
}

uint64_t GetInstructionPointer(const GRegSet& gregs) { return gregs.pc; }

}  // namespace silifuzz
