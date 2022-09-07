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

void LogGRegs(const GRegSet& gregs, const GRegSet* base, bool log_diff) {
  LogGRegs(gregs, &LogInfoLogger, nullptr, base, log_diff);
}

void LogFPRegs(const FPRegSet& fpregs, bool log_fp_data, const FPRegSet* base,
               bool log_diff) {
  LogFPRegs(fpregs, log_fp_data, &LogInfoLogger, nullptr, base, log_diff);
}

void LogSignalRegs(const SignalRegSet& sigregs, const SignalRegSet* base,
                   bool log_diff) {
  LogSignalRegs(sigregs, &LogInfoLogger, nullptr, base, log_diff);
}

}  // namespace silifuzz
