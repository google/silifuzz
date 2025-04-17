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

#include <cstring>
#include <iterator>

#include "./util/arch.h"
#include "./util/internal/logging_util_macros.h"
#include "./util/itoa.h"
#include "./util/reg_group_io.h"
#include "./util/reg_group_set.h"
#include "./util/strcat.h"
#include "./util/ucontext/signal.h"
#include "./util/ucontext/ucontext_types.h"

namespace silifuzz {

template <>
void LogGRegs(const GRegSet<X86_64>& regs, RegsLogger logger, void* logger_arg,
              const GRegSet<X86_64>* base, bool log_diff) {
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

template <>
void LogFPRegs(const FPRegSet<X86_64>& regs, bool log_fp_data,
               RegsLogger logger, void* logger_arg,
               const FPRegSet<X86_64>* base, bool log_diff) {
  LOG_ONE_REG(fcw);
  LOG_ONE_REG(fsw);
  LOG_ONE_REG(ftw);
  LOG_ONE_REG(fop);
  LOG_ONE_REG(rip);
  LOG_ONE_REG(rdp);
  LOG_ONE_REG(mxcsr);
  LOG_ONE_REG(mxcsr_mask);

  if (log_fp_data) {
    if (base == nullptr) (*logger)(logger_arg, "--", "", "", "");

    for (int i = 0; i < std::size(regs.st); ++i) {
      LOG_INDEXED_REG(st, i);
    }

    for (int i = 0; i < std::size(regs.xmm); ++i) {
      LOG_INDEXED_REG(xmm, i);
    }
  }
}

template <>
void LogERegs(const RegisterGroupIOBuffer<X86_64>& regs, RegsLogger logger,
              void* logger_arg, const RegisterGroupIOBuffer<X86_64>* base,
              bool log_diff) {
  if (regs.register_groups.GetAVX()) {
    for (int i = 0; i < regs.kNumYmms; ++i) {
      LOG_INDEXED_BIG_REG(ymm, i, regs.kYmmSizeBytes);
    }
  }
  if (regs.register_groups.GetAVX512()) {
    if (base == nullptr && regs.register_groups.GetAVX())
      (*logger)(logger_arg, "--", "", "", "");
    for (int i = 0; i < regs.kNumZmms; ++i) {
      LOG_INDEXED_BIG_REG(zmm, i, regs.kZmmSizeBytes);
    }
    if (base == nullptr) (*logger)(logger_arg, "--", "", "", "");
    for (int i = 0; i < regs.kNumOpmasks; ++i) {
      LOG_INDEXED_REG(opmask, i);
    }
  }
}

#if defined(__x86_64__)
void LogSignalRegs(const SignalRegSet& regs, RegsLogger logger,
                   void* logger_arg, const SignalRegSet* base, bool log_diff) {
  LOG_ONE_REG(err);
  LOG_ONE_REG(cr2);
  LOG_ONE_REG(trapno);
}
#endif

// StrCat values are short-lived, we need copy them into buffers.
template <>
void GroupSetToStr<X86_64>(const RegisterGroupSet<X86_64>& groups,
                           char* buffer) {
  // nolibc does not even have strncpy.  Just copy the whole StrCat buffer.
  memcpy(
      buffer,
      StrCat<kMaxGroupSetStringLength>(
          {HexStr(groups.Serialize()), " [", groups.GetGPR() ? " GPR" : "",
           groups.GetFPRAndSSE() ? " FPR_AND_SSE" : "",
           groups.GetAVX() ? " AVX" : "", groups.GetAVX512() ? " AVX512" : "",
           groups.GetAMX() ? " AMX" : "", " ]"}),
      kMaxGroupSetStringLength);
}

#undef LOG_ONE_REG
#undef LOG_INDEXED_REG

}  // namespace silifuzz
