// Copyright 2025 The SiliFuzz Authors.
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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_USER_REGS_UTIL_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_USER_REGS_UTIL_H_

#include <sys/user.h>

#include <cstdint>

namespace silifuzz {

#if defined(__x86_64__)
inline uint64_t GetIPFromUserRegs(const user_regs_struct& regs) {
  return regs.rip;
}

inline uint64_t GetSPFromUserRegs(const user_regs_struct& regs) {
  return regs.rsp;
}

inline uint64_t GetSyscallNumberFromUserRegs(const user_regs_struct& regs) {
  // Some syscalls clobber rax but orig_rax preserves the value.
  return regs.orig_rax;
}

#elif defined(__aarch64__)
inline uint64_t GetIPFromUserRegs(const user_regs_struct& regs) {
  return regs.pc;
}

inline uint64_t GetSPFromUserRegs(const user_regs_struct& regs) {
  return regs.sp;
}

inline uint64_t GetSyscallNumberFromUserRegs(const user_regs_struct& regs) {
  return regs.regs[8];
}
#else
#error "Unsupported architecture"
#endif
}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_USER_REGS_UTIL_H_
