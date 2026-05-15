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
#include <cstring>
#include <type_traits>

#include "./util/arch.h"
#include "./util/ucontext/ucontext_types.h"

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

static_assert(std::is_trivially_copyable_v<GRegSet<X86_64>>,
              "Must be trivially copyable for memset");
static_assert(std::is_standard_layout_v<GRegSet<X86_64>>,
              "Must be standard layout for deterministic zeroing");
static_assert(std::is_trivially_copyable_v<user_regs_struct>,
              "Must be trivially copyable for memset");

static_assert(std::is_trivially_copyable_v<FPRegSet<X86_64>>,
              "Must be trivially copyable for memcpy");
static_assert(std::is_standard_layout_v<FPRegSet<X86_64>>,
              "Must be standard layout");
static_assert(std::is_trivially_copyable_v<user_fpregs_struct>,
              "Must be trivially copyable for memcpy");

inline void ConvertUserRegsToGRegSet(const user_regs_struct& regs,
                                     GRegSet<X86_64>* dst) {
  // Zero-initialize to ensure deterministic behavior (e.g. for comparisons)
  // and prevent leaking uninitialized stack memory in padding/reserved bytes.
  memset(dst, 0, sizeof(*dst));
  dst->r8 = regs.r8;
  dst->r9 = regs.r9;
  dst->r10 = regs.r10;
  dst->r11 = regs.r11;
  dst->r12 = regs.r12;
  dst->r13 = regs.r13;
  dst->r14 = regs.r14;
  dst->r15 = regs.r15;
  dst->rdi = regs.rdi;
  dst->rsi = regs.rsi;
  dst->rbp = regs.rbp;
  dst->rbx = regs.rbx;
  dst->rdx = regs.rdx;
  dst->rax = regs.rax;
  dst->rcx = regs.rcx;
  dst->rsp = regs.rsp;
  dst->rip = regs.rip;
  dst->eflags = regs.eflags;
  dst->fs_base = regs.fs_base;
  dst->gs_base = regs.gs_base;
  dst->cs = regs.cs;
  dst->gs = regs.gs;
  dst->fs = regs.fs;
  dst->ss = regs.ss;
  dst->ds = regs.ds;
  dst->es = regs.es;
  dst->padding = 0;
}

inline void ConvertGRegSetToUserRegs(const GRegSet<X86_64>& gregs,
                                     user_regs_struct* user_gregs) {
  // Zero-initialize to ensure deterministic behavior (e.g. for comparisons)
  // and prevent leaking uninitialized stack memory in padding/reserved bytes.
  memset(user_gregs, 0, sizeof(*user_gregs));
  user_gregs->r8 = gregs.r8;
  user_gregs->r9 = gregs.r9;
  user_gregs->r10 = gregs.r10;
  user_gregs->r11 = gregs.r11;
  user_gregs->r12 = gregs.r12;
  user_gregs->r13 = gregs.r13;
  user_gregs->r14 = gregs.r14;
  user_gregs->r15 = gregs.r15;
  user_gregs->rdi = gregs.rdi;
  user_gregs->rsi = gregs.rsi;
  user_gregs->rbp = gregs.rbp;
  user_gregs->rbx = gregs.rbx;
  user_gregs->rdx = gregs.rdx;
  user_gregs->rax = gregs.rax;
  user_gregs->rcx = gregs.rcx;
  user_gregs->rsp = gregs.rsp;
  user_gregs->rip = gregs.rip;
  user_gregs->eflags = gregs.eflags;
  user_gregs->fs_base = gregs.fs_base;
  user_gregs->gs_base = gregs.gs_base;
  user_gregs->orig_rax = user_gregs->rax;  // for lack of anything else
  user_gregs->cs = gregs.cs;
  user_gregs->gs = gregs.gs;
  user_gregs->fs = gregs.fs;
  user_gregs->ss = gregs.ss;
  user_gregs->ds = gregs.ds;
  user_gregs->es = gregs.es;
}

inline void ConvertUserFPRegsToFPRegSet(const user_fpregs_struct& fp_regs,
                                        FPRegSet<X86_64>* dst) {
  static_assert(sizeof(user_fpregs_struct) == sizeof(FPRegSet<X86_64>),
                "Size mismatch between user_fpregs_struct and FPRegSet");
  memcpy(dst, &fp_regs, sizeof(*dst));
}

inline void ConvertFPRegSetToUserFPRegs(const FPRegSet<X86_64>& fp_reg_set,
                                        user_fpregs_struct* dst) {
  static_assert(sizeof(user_fpregs_struct) == sizeof(FPRegSet<X86_64>),
                "Size mismatch between user_fpregs_struct and FPRegSet");
  memcpy(dst, &fp_reg_set, sizeof(*dst));
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

static_assert(std::is_trivially_copyable_v<GRegSet<AArch64>>,
              "Must be trivially copyable for memset");
static_assert(std::is_standard_layout_v<GRegSet<AArch64>>,
              "Must be standard layout for deterministic zeroing");
static_assert(std::is_trivially_copyable_v<user_regs_struct>,
              "Must be trivially copyable for memset");

static_assert(std::is_trivially_copyable_v<FPRegSet<AArch64>>,
              "Must be trivially copyable for memset");
static_assert(std::is_standard_layout_v<FPRegSet<AArch64>>,
              "Must be standard layout");
static_assert(std::is_trivially_copyable_v<user_fpsimd_struct>,
              "Must be trivially copyable for memset");

inline void ConvertUserRegsToGRegSet(const user_regs_struct& regs,
                                     GRegSet<AArch64>* dst) {
  // Zero-initialize to ensure deterministic behavior (e.g. for comparisons)
  // and prevent leaking uninitialized stack memory in padding/reserved bytes.
  memset(dst, 0, sizeof(*dst));
  for (size_t i = 0; i < 31; ++i) {
    dst->x[i] = regs.regs[i];
  }
  dst->sp = regs.sp;
  dst->pc = regs.pc;
  dst->pstate = regs.pstate & kPStateMask;
}

inline void ConvertGRegSetToUserRegs(const GRegSet<AArch64>& gregs,
                                     user_regs_struct* dst) {
  // Zero-initialize to ensure deterministic behavior (e.g. for comparisons)
  // and prevent leaking uninitialized stack memory in padding/reserved bytes.
  memset(dst, 0, sizeof(*dst));
  for (size_t i = 0; i < 31; ++i) {
    dst->regs[i] = gregs.x[i];
  }
  dst->sp = gregs.sp;
  dst->pc = gregs.pc;
  dst->pstate = gregs.pstate;
}

inline void ConvertUserFPRegsToFPRegSet(const user_fpsimd_struct& fp_regs,
                                        FPRegSet<AArch64>* dst) {
  // Zero-initialize to ensure deterministic behavior (e.g. for comparisons)
  // and prevent leaking uninitialized stack memory in padding/reserved bytes.
  memset(dst, 0, sizeof(*dst));
  for (size_t i = 0; i < 32; ++i) {
    dst->v[i] = fp_regs.vregs[i];
  }
  dst->fpsr = fp_regs.fpsr;
  dst->fpcr = fp_regs.fpcr;
}

inline void ConvertFPRegSetToUserFPRegs(const FPRegSet<AArch64>& fp_reg_set,
                                        user_fpsimd_struct* dst) {
  // Zero-initialize to ensure deterministic behavior (e.g. for comparisons)
  // and prevent leaking uninitialized stack memory in padding/reserved bytes.
  memset(dst, 0, sizeof(*dst));
  for (size_t i = 0; i < 32; ++i) {
    dst->vregs[i] = fp_reg_set.v[i];
  }
  dst->fpsr = fp_reg_set.fpsr;
  dst->fpcr = fp_reg_set.fpcr;
}

#else
#error "Unsupported architecture"
#endif
}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_USER_REGS_UTIL_H_
