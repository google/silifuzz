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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_UCONTEXT_UCONTEXT_TYPES_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_UCONTEXT_UCONTEXT_TYPES_H_

#include <string.h>  // for memcmp()

#include <cstdint>

#include "./util/arch.h"

namespace silifuzz {

// Values for all general-purpose CPU registers.
template <typename Arch>
struct GRegSet;

// This has the same layout as gregset_t from ucontext_t up to the ss field
// (our test verifies that), but overall this has the exact structure
// of (and only) the register state that can be saved - see SaveUContext().
template <>
struct GRegSet<X86_64> {
  uint64_t r8;
  uint64_t r9;
  uint64_t r10;
  uint64_t r11;
  uint64_t r12;
  uint64_t r13;
  uint64_t r14;
  uint64_t r15;
  uint64_t rdi;
  uint64_t rsi;
  uint64_t rbp;
  uint64_t rbx;
  uint64_t rdx;
  uint64_t rax;
  uint64_t rcx;
  uint64_t rsp;
  uint64_t rip;
  uint64_t eflags;
  uint16_t cs;
  uint16_t gs;
  uint16_t fs;
  uint16_t ss;  // padding in gregset_t; fields after this differ from gregset_t
  uint16_t ds;
  uint16_t es;
  uint32_t padding;  // so that sizeof(GRegSet) is a multiple of int64, so that
                     // there is no unnamed padding in UContext below
                     // (our test verifies this)
  // FS_BASE and GS_BASE are hidden base registers used to compute fs: and gs:
  // relative addresses in 64-bit mode.
  // See "4.5.3 Segment Registers in 64-Bit Mode" in  AMD64 Architecture
  // Programmer’s Manual Volume 2: System Programming
  // https://www.amd.com/system/files/TechDocs/24593.pdf
  // On Linux fs_base is typically used to refer to TLS data.
  uint64_t fs_base;
  uint64_t gs_base;

  using Arch = X86_64;

  uint64_t GetInstructionPointer() const { return rip; }

  void SetInstructionPointer(uint64_t value) { rip = value; }

  uint64_t GetStackPointer() const { return rsp; }

  void SetStackPointer(uint64_t value) { rsp = value; }
};

template <>
struct GRegSet<AArch64> {
  uint64_t x[31];
  uint64_t sp;
  uint64_t pc;
  uint64_t pstate;
  uint64_t tpidr;
  uint64_t tpidrro;

  using Arch = AArch64;

  // Note: aarch64 would call this the "program counter" but we're defaulting to
  // x86_64 terminology when we need to make an arbitrary choice for an
  // architecture-neutral name.
  uint64_t GetInstructionPointer() const { return pc; }

  void SetInstructionPointer(uint64_t value) { pc = value; }

  uint64_t GetStackPointer() const { return sp; }

  void SetStackPointer(uint64_t value) { sp = value; }
};

// Convenience equality on GRegSet (all bytes are compared).
template <typename Arch>
inline bool operator==(const GRegSet<Arch>& x, const GRegSet<Arch>& y) {
  return 0 == memcmp(&x, &y, sizeof(x));
}

// The bits of pstate that are saved and restored.
// Currently this is only NZCV.
constexpr uint64_t kPStateMask = 0b1111'0000'0000'0000'0000'0000'0000'0000;

// ========================================================================= //

template <typename Arch>
struct FPRegSet;

// This structure follows the format of fxsave64 / fxrstor64.
// See:
// https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2a-manual.pdf
// Table 3-46
// But we use AMD names where they differ. See:
// https://www.amd.com/system/files/TechDocs/24592.pdf
// Must be 16-byte aligned so it can be used with these instructions.
template <>
struct FPRegSet<X86_64> {
  uint16_t fcw;       // x87 FPU control word.
  uint16_t fsw;       // x87 FPU status word.
  uint8_t ftw;        // Abridged x87 FPU tag word.
  uint8_t reserved0;  // The libc struct makes this part of ftw.
  uint16_t fop;       // x87 FPU opcode.
  uint64_t rip;       // x87 FPU instruction pointer offset.
  uint64_t rdp;       // x87 FPU data pointer offset.
  uint32_t mxcsr;     // SSE control and status information.
  uint32_t mxcsr_mask;

  // x87 FPU (80-bit) or MMX (64-bit) registers padded to 128 bits.
  __uint128_t st[8];

  // SSE registers.
  __uint128_t xmm[16];

  // Not yet defined by spec.
  uint8_t padding[96];

  using Arch = X86_64;
};
static_assert(sizeof(FPRegSet<X86_64>) == 512, "FPRegSet has unexpected size.");
static_assert(alignof(FPRegSet<X86_64>) == 16,
              "FPRegSet has unexpected alignment.");

// Note: libc stores fpsr and fpcr as 32-bit values. This structure stores them
// as 64-bit values because that is they way they are specified. Currently the
// upper 32-bits are zero, but that could technically change.
template <>
struct FPRegSet<AArch64> {
  __uint128_t v[32];
  uint64_t fpsr;
  uint64_t fpcr;

  using Arch = AArch64;
};
static_assert(alignof(FPRegSet<AArch64>) == 16,
              "FPRegSet has unexpected alignment.");

// Convenience equality on FPRegSet (all bytes are compared).
template <typename Arch>
inline bool operator==(const FPRegSet<Arch>& x, const FPRegSet<Arch>& y) {
  return 0 == memcmp(&x, &y, sizeof(x));
}

// ========================================================================= //

// UContext contains complete user-space CPU execution context state.
//
// Very similar to ucontext_t from libc, but unlike it:
// * We have a convenient way of accessing general registers (struct fields vs.
//   indexing into an array - see GRegSet above).
// * We have space for all segment registers.
// * We do not store data unrelated to CPU state.
// * We guarantee alignment of 16 for FPRegSet field, so that
//   our context saving/restoring implementations can easily use the fxsave and
//   fxrstor instructions that require this alignment.
template <typename T>
struct UContext {
  FPRegSet<T> fpregs;
  GRegSet<T> gregs;

  using Arch = T;
};

#define ARCH_OF(var) typename decltype(var)::Arch

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_UCONTEXT_UCONTEXT_TYPES_H_
