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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_UCONTEXT_X86_64_TRAPS_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_UCONTEXT_X86_64_TRAPS_H_

#include <cstdint>

namespace silifuzz {

// Mirrors x86_pf_error_code enum of the Linux kernel. Unused enum values
// are omitted.
// The values represent bits of uc_mcontext.gregs[REG_ERR] passed via ucontext_t
// argument to the sigsegv handler when TRAP_NO == X86_TRAP_PF.
// See https://stackoverflow.com/questions/17671869 for details.
struct X86PFError {
  enum Type {
    PF_PROT_BIT = 1 << 0,   // 0: no page found, 1: protection fault
    PF_WRITE_BIT = 1 << 1,  // 0: read access, 1: write access
    PF_USER_BIT = 1 << 2,   // 0: kernel-mode access, 1: user-mode
    PF_INSTR_BIT = 1 << 4,  // 1: fault was an instruction fetch
  };
};

// https://wiki.osdev.org/Exceptions
struct X86Exception {
  // Borrowed from google3/cloud/gvisor/standalone/gr0/traps.h
  // SiliFuzz does not handle most of these, they are only listed for
  // completeness.
  enum Type {
    X86_TRAP_DE = 0,     //  0, Divide-by-zero
    X86_TRAP_DB,         //  1, Debug
    X86_TRAP_NMI,        //  2, Non-maskable Interrupt
    X86_TRAP_BP,         //  3, Breakpoint
    X86_TRAP_OF,         //  4, Overflow
    X86_TRAP_BR,         //  5, Bound Range Exceeded
    X86_TRAP_UD,         //  6, Invalid Opcode
    X86_TRAP_NM,         //  7, Device Not Available
    X86_TRAP_DF,         //  8, Double Fault
    X86_TRAP_OLD_MF,     //  9, Coprocessor Segment Overrun
    X86_TRAP_TS,         // 10, Invalid TSS
    X86_TRAP_NP,         // 11, Segment Not Present
    X86_TRAP_SS,         // 12, Stack Segment Fault
    X86_TRAP_GP,         // 13, General Protection Fault
    X86_TRAP_PF,         // 14, Page Fault
    X86_TRAP_SPURIOUS,   // 15, Spurious Interrupt
    X86_TRAP_MF,         // 16, x87 Floating-Point Exception
    X86_TRAP_AC,         // 17, Alignment Check
    X86_TRAP_MC,         // 18, Machine Check
    X86_TRAP_XF,         // 19, SIMD Floating-Point Exception
    X86_TRAP_IRET = 32,  // 32, IRET Exception
  };
};

// X86 trap flag (TF) value. Same as X86_EFLAGS_TF in kernel sources.
// https://en.wikipedia.org/wiki/Trap_flag
inline constexpr uint64_t kX86TrapFlag = 0x100;

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_UCONTEXT_X86_64_TRAPS_H_
