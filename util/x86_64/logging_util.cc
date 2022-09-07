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

#define LOG_INDEXED_REG(reg_name, index, data, base_data)                     \
  if (base == nullptr || data[index] != base_data[index]) {                   \
    (*logger)(logger_arg, StrCat({#reg_name "[", IntStr(index), "] = "}),     \
              HexStr(data[index]),                                            \
              (log_diff && base != nullptr) ? " want " : "",                  \
              (log_diff && base != nullptr) ? HexStr(base_data[index]) : ""); \
  }

void LogGRegs(const GRegSet& regs, RegsLogger logger, void* logger_arg,
              const GRegSet* base, bool log_diff) {
  LOG_ONE_REG(rax);
  LOG_ONE_REG(rbx);
  LOG_ONE_REG(rcx);
  LOG_ONE_REG(rdx);
  LOG_ONE_REG(rdi);
  LOG_ONE_REG(rsi);
  LOG_ONE_REG(rbp);
  if (base == nullptr) (*logger)(logger_arg, "--", "", "", "");
  LOG_ONE_REG(rsp);
  LOG_ONE_REG(rip);
  if (base == nullptr) (*logger)(logger_arg, "--", "", "", "");
  LOG_ONE_REG(r8);
  LOG_ONE_REG(r9);
  LOG_ONE_REG(r10);
  LOG_ONE_REG(r11);
  LOG_ONE_REG(r12);
  LOG_ONE_REG(r13);
  LOG_ONE_REG(r14);
  LOG_ONE_REG(r15);
  if (base == nullptr) (*logger)(logger_arg, "--", "", "", "");
  LOG_ONE_REG(eflags);
  if (base == nullptr) (*logger)(logger_arg, "--", "", "", "");
  LOG_ONE_REG(fs_base);
  LOG_ONE_REG(gs_base);
  LOG_ONE_REG(cs);
  LOG_ONE_REG(gs);
  LOG_ONE_REG(fs);
  LOG_ONE_REG(ss);
  LOG_ONE_REG(ds);
  LOG_ONE_REG(es);
}

void LogFPRegs(const FPRegSet& regs, bool log_fp_data, RegsLogger logger,
               void* logger_arg, const FPRegSet* base, bool log_diff) {
  LOG_ONE_REG(cwd);
  LOG_ONE_REG(swd);
  LOG_ONE_REG(ftw);
  LOG_ONE_REG(fop);
  LOG_ONE_REG(rip);
  LOG_ONE_REG(rdp);
  LOG_ONE_REG(mxcsr);
  LOG_ONE_REG(mxcr_mask);

  if (log_fp_data) {
    if (base == nullptr) (*logger)(logger_arg, "--", "", "", "");

    // Use the sys/user.h interpetation of the floating point data rather than
    // the sys/ucontext.h interpretation.  It's easier to log.

    auto st_space = reinterpret_cast<const __uint128_t*>(regs._st);
    auto base_st_space =
        base ? reinterpret_cast<const __uint128_t*>(base->_st) : nullptr;
    constexpr int st_count = 8;
    static_assert(sizeof(*st_space) * st_count == sizeof(regs._st),
                  "Size of _st does not match assumptions.");

    for (int i = 0; i < st_count; ++i) {
      LOG_INDEXED_REG(st, i, st_space, base_st_space);
    }

    auto xmm_space = reinterpret_cast<const __uint128_t*>(regs._xmm);
    auto base_xmm_space =
        base ? reinterpret_cast<const __uint128_t*>(base->_xmm) : nullptr;
    constexpr int xmm_count = 16;
    static_assert(sizeof(*xmm_space) * xmm_count == sizeof(regs._xmm),
                  "Size of _xmm does not match assumptions.");

    for (int i = 0; i < xmm_count; ++i) {
      LOG_INDEXED_REG(xmm, i, xmm_space, base_xmm_space);
    }
  }
}

void LogSignalRegs(const SignalRegSet& regs, RegsLogger logger,
                   void* logger_arg, const SignalRegSet* base, bool log_diff) {
  LOG_ONE_REG(err);
  LOG_ONE_REG(cr2);
  LOG_ONE_REG(trapno);
}

#undef LOG_ONE_REG
#undef LOG_INDEXED_REG

}  // namespace silifuzz
