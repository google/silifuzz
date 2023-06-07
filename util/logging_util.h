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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_LOGGING_UTIL_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_LOGGING_UTIL_H_

// This library contains various simple utilities to help nicely log
// register states.

#include "./util/reg_checksum.h"
#include "./util/ucontext/signal.h"
#include "./util/ucontext/ucontext_types.h"

namespace silifuzz {

// LOG_INFO()-s all general register values from a GRegSet.
// Log lines will be prefixed with two spaces.
// For `base` and `log_diff` see LogGRegs() overload below.
template <typename Arch>
void LogGRegs(const GRegSet<Arch>& gregs, const GRegSet<Arch>* base = nullptr,
              bool log_diff = false);

// LOG_INFO()-s all general register values from a FPRegSet.
// log_fp_data tells if the fp data regs should be logged or not.
// Log lines will be prefixed with two spaces.
// For `base` and `log_diff` see LogFPRegs() overload below.
template <typename Arch>
void LogFPRegs(const FPRegSet<Arch>& fpregs, bool log_fp_data = true,
               const FPRegSet<Arch>* base = nullptr, bool log_diff = false);

// LOG_INFO()-s all register values from a SignalRegSet.
// Log lines will be prefixed with two spaces.
void LogSignalRegs(const SignalRegSet& sigregs,
                   const SignalRegSet* base = nullptr, bool log_diff = false);

// LOG_INFO()-s register checksum.
// Log lines will be prefixed with two spaces.
// For `base` and `log_diff` see LogRegisterChecksum() overload below.
template <typename Arch>
void LogRegisterChecksum(const RegisterChecksum<Arch>& register_checksum,
                         const RegisterChecksum<Arch>* base = nullptr,
                         bool log_diff = false);

// ----------------------------------------------------------------------- //

// A lower-level variants of LogGRegs() and LogFPRegs() that
// * Take RegsLogger function and an argument for it.
//   (We use this interface instead of std::function<> so that this library
//   can be used in the nolibc context - no allocations.)
// * Take an optional `base` value of the registers: if given it will
//   suppress logging of the registers that have the same value as in `base`.
// * Take an optional `log_diff` value. When true, and `base` was provided will
//   log the `base` value for each register next to the actual value. Useful for
//   side-by-side comparison.
using RegsLogger = void (*)(void* logger_arg, const char* str1,
                            const char* str2, const char* str3,
                            const char* str4);

template <typename Arch>
void LogGRegs(const GRegSet<Arch>& gregs, RegsLogger logger, void* logger_arg,
              const GRegSet<Arch>* base = nullptr, bool log_diff = false);
template <typename Arch>
void LogFPRegs(const FPRegSet<Arch>& fpregs, bool log_fp_data,
               RegsLogger logger, void* logger_arg,
               const FPRegSet<Arch>* base = nullptr, bool log_diff = false);
void LogSignalRegs(const SignalRegSet& gregs, RegsLogger logger,
                   void* logger_arg, const SignalRegSet* base = nullptr,
                   bool log_diff = false);
template <typename Arch>
void LogRegisterChecksum(const RegisterChecksum<Arch>& register_checksum,
                         RegsLogger logger, void* logger_arg,
                         const RegisterChecksum<Arch>* base = nullptr,
                         bool log_diff = false);

// Internal helper function to convert a register group set into a string.
// This is used in nolibc environment so we specify a maximum string size.
// buffer must hold at least kMaxGroupSetStringLeng bytes.
constexpr size_t kMaxGroupSetStringLength = 128;
template <typename Arch>
void GroupSetToStr(const RegisterGroupSet<Arch>& groups, char* buffer);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_LOGGING_UTIL_H_
