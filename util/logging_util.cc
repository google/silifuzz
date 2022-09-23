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

#include "./util/checks.h"

namespace silifuzz {

// An allocation-free "lambda" for implementing LogGRegs() and LogFPRegs().
static void LogInfoLogger(void* /*logger_arg*/, const char* str1,
                          const char* str2, const char* str3,
                          const char* str4) {
  LOG_INFO("  ", str1, str2, str3, str4);
}

template <typename Arch>
void LogGRegs(const GRegSet<Arch>& gregs, const GRegSet<Arch>* base,
              bool log_diff) {
  LogGRegs(gregs, &LogInfoLogger, nullptr, base, log_diff);
}

// TODO(ncbray): compile in both arch-specific versions.
#if defined(__x86_64__)
template void LogGRegs(const GRegSet<X86_64>& gregs,
                       const GRegSet<X86_64>* base, bool log_diff);
#elif defined(__aarch64__)
template void LogGRegs(const GRegSet<AArch64>& gregs,
                       const GRegSet<AArch64>* base, bool log_diff);
#else
#error "Unsupported architecture"
#endif

template <typename Arch>
void LogFPRegs(const FPRegSet<Arch>& fpregs, bool log_fp_data,
               const FPRegSet<Arch>* base, bool log_diff) {
  LogFPRegs(fpregs, log_fp_data, &LogInfoLogger, nullptr, base, log_diff);
}

// TODO: compile in both arch-specific versions.
#if defined(__x86_64__)
template void LogFPRegs(const FPRegSet<X86_64>& gregs, bool log_fp_data,
                        const FPRegSet<X86_64>* base, bool log_diff);
#elif defined(__aarch64__)
template void LogFPRegs(const FPRegSet<AArch64>& gregs, bool log_fp_data,
                        const FPRegSet<AArch64>* base, bool log_diff);
#else
#error "Unsupported architecture"
#endif

void LogSignalRegs(const SignalRegSet& sigregs, const SignalRegSet* base,
                   bool log_diff) {
  LogSignalRegs(sigregs, &LogInfoLogger, nullptr, base, log_diff);
}

}  // namespace silifuzz
