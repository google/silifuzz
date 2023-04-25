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

#include <stdint.h>

#include "absl/base/macros.h"
#include "./util/itoa.h"
#include "./util/strcat.h"

namespace silifuzz {

// Macro (vs a function) helps up to easily log the names of the registers
// in both LogGRegs() and LogFPRegs() below.
#define LOG_ONE_REG(reg_name)                                               \
  if (base == nullptr || regs.reg_name != base->reg_name) {                 \
    (*logger)(logger_arg, #reg_name " = ", HexStr(regs.reg_name),           \
              (log_diff && base != nullptr) ? " want " : "",                \
              (log_diff && base != nullptr) ? HexStr(base->reg_name) : ""); \
  }

#define LOG_INDEXED_REG(reg_name, index)                                     \
  if (base == nullptr || regs.reg_name[index] != base->reg_name[index]) {    \
    (*logger)(                                                               \
        logger_arg, StrCat({#reg_name "[", IntStr(index), "] = "}),          \
        HexStr(regs.reg_name[index]),                                        \
        (log_diff && base != nullptr) ? " want " : "",                       \
        (log_diff && base != nullptr) ? HexStr(base->reg_name[index]) : ""); \
  }

template <>
void LogGRegs(const GRegSet<AArch64>& regs, RegsLogger logger, void* logger_arg,
              const GRegSet<AArch64>* base, bool log_diff) {
  for (int i = 0; i < ABSL_ARRAYSIZE(regs.x); ++i) {
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
    for (int i = 0; i < ABSL_ARRAYSIZE(regs.v); ++i) {
      LOG_INDEXED_REG(v, i);
    }
    if (base == nullptr) (*logger)(logger_arg, "--", "", "", "");
  }
  LOG_ONE_REG(fpsr);
  LOG_ONE_REG(fpcr);
}

#if defined(__aarch64__)
void LogSignalRegs(const SignalRegSet& regs, RegsLogger logger,
                   void* logger_arg, const SignalRegSet* base, bool log_diff) {
  LOG_ONE_REG(esr);
}
#endif

#undef LOG_ONE_REG
#undef LOG_INDEXED_REG

}  // namespace silifuzz
