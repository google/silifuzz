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

#include "./util/logging_util.h"

#include <sys/types.h>

#include <cstring>
#include <iterator>

#include "./util/arch.h"
#include "./util/internal/logging_util_macros.h"
#include "./util/itoa.h"
#include "./util/reg_group_io.h"
#include "./util/reg_group_set.h"
#include "./util/strcat.h"
#include "./util/ucontext/ucontext_types.h"

namespace silifuzz {

template <>
void LogGRegs(const GRegSet<AArch64>& regs, RegsLogger logger, void* logger_arg,
              const GRegSet<AArch64>* base, bool log_diff) {
  for (int i = 0; i < std::size(regs.x); ++i) {
    LOG_INDEXED_REG(x, i);
  }
  if (base == nullptr) (*logger)(logger_arg, "--", "", "", "");
  LOG_ONE_REG(sp);
  LOG_ONE_REG(pc);
  LOG_ONE_REG(pstate);
  LOG_ONE_REG(tpidr);
  LOG_ONE_REG(tpidrro);
}

template <>
void LogFPRegs(const FPRegSet<AArch64>& regs, bool log_fp_data,
               RegsLogger logger, void* logger_arg,
               const FPRegSet<AArch64>* base, bool log_diff) {
  if (log_fp_data) {
    for (int i = 0; i < std::size(regs.v); ++i) {
      LOG_INDEXED_REG(v, i);
    }
    if (base == nullptr) (*logger)(logger_arg, "--", "", "", "");
  }
  LOG_ONE_REG(fpsr);
  LOG_ONE_REG(fpcr);
}

template <>
void LogERegs(const RegisterGroupIOBuffer<AArch64>& regs, RegsLogger logger,
              void* logger_arg, const RegisterGroupIOBuffer<AArch64>* base,
              bool log_diff) {
  const size_t vl = regs.register_groups.GetSVEVectorWidth();
  if (vl == 0) {
    return;
  }
  for (int i = 0; i < 32; ++i) {
    LOG_INDEXED_BIG_REG(z, i, vl);
  }
  if (base == nullptr) (*logger)(logger_arg, "--", "", "", "");
  for (int i = 0; i < 16; ++i) {
    LOG_INDEXED_BIG_REG(p, i, vl / 8);
  }
  if (base == nullptr) (*logger)(logger_arg, "--", "", "", "");
  LOG_INDEXED_BIG_REG(ffr, 0, vl / 8);
}

#if defined(__aarch64__)
void LogSignalRegs(const SignalRegSet& regs, RegsLogger logger,
                   void* logger_arg, const SignalRegSet* base, bool log_diff) {
  LOG_ONE_REG(esr);
}
#endif

// StrCat values are short-lived, we need copy them into buffers.
template <>
void GroupSetToStr<AArch64>(const RegisterGroupSet<AArch64>& groups,
                            char* buffer) {
  // nolibc does not even have strncpy. Just copy the whole StrCat buffer.
  memcpy(buffer,
         StrCat<kMaxGroupSetStringLength>(
             {HexStr(groups.Serialize()), " [", groups.GetGPR() ? " GPR" : "",
              groups.GetFPR() ? " FPR" : "", " ]"}),
         kMaxGroupSetStringLength);
}

#undef LOG_ONE_REG
#undef LOG_INDEXED_REG

}  // namespace silifuzz
