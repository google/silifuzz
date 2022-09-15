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

#include "./util/ucontext/signal_test.h"

#include "gtest/gtest.h"
#include "./util/ucontext/signal.h"
#include "./util/ucontext/ucontext.h"
#include "./util/ucontext/x86_64/traps.h"

namespace silifuzz {
namespace {

void pattern_init(void* data, size_t size, size_t seed) {
  uint16_t* ptr = reinterpret_cast<uint16_t*>(data);
  for (int i = 0; i < size / sizeof(*ptr); ++i) {
    ptr[i] = (uint16_t)(seed + i) * 63073;
  }
}

// Check that our GRegSet has the same layout to gregset_t from ucontext_t
// up to the point where they diverge (the ss field).
// This will lets use byte-copy or cast between them if only using these
// shared fields.
TEST(SignalTest, GRegOffsets) {
#define REG_OFFSET(REG)                                 \
  (offsetof(ucontext_t, uc_mcontext.gregs[REG_##REG]) - \
   offsetof(ucontext_t, uc_mcontext.gregs))

  EXPECT_EQ(offsetof(GRegSet, r8), REG_OFFSET(R8));
  EXPECT_EQ(offsetof(GRegSet, r9), REG_OFFSET(R9));
  EXPECT_EQ(offsetof(GRegSet, r10), REG_OFFSET(R10));
  EXPECT_EQ(offsetof(GRegSet, r11), REG_OFFSET(R11));
  EXPECT_EQ(offsetof(GRegSet, r12), REG_OFFSET(R12));
  EXPECT_EQ(offsetof(GRegSet, r13), REG_OFFSET(R13));
  EXPECT_EQ(offsetof(GRegSet, r14), REG_OFFSET(R14));
  EXPECT_EQ(offsetof(GRegSet, r15), REG_OFFSET(R15));
  EXPECT_EQ(offsetof(GRegSet, rdi), REG_OFFSET(RDI));
  EXPECT_EQ(offsetof(GRegSet, rsi), REG_OFFSET(RSI));
  EXPECT_EQ(offsetof(GRegSet, rbp), REG_OFFSET(RBP));
  EXPECT_EQ(offsetof(GRegSet, rbx), REG_OFFSET(RBX));
  EXPECT_EQ(offsetof(GRegSet, rdx), REG_OFFSET(RDX));
  EXPECT_EQ(offsetof(GRegSet, rax), REG_OFFSET(RAX));
  EXPECT_EQ(offsetof(GRegSet, rcx), REG_OFFSET(RCX));
  EXPECT_EQ(offsetof(GRegSet, rsp), REG_OFFSET(RSP));
  EXPECT_EQ(offsetof(GRegSet, rip), REG_OFFSET(RIP));
  EXPECT_EQ(offsetof(GRegSet, eflags), REG_OFFSET(EFL));
  EXPECT_EQ(offsetof(GRegSet, cs), REG_OFFSET(CSGSFS));
  EXPECT_EQ(offsetof(GRegSet, gs), REG_OFFSET(CSGSFS) + sizeof(GRegSet::cs));
  EXPECT_EQ(offsetof(GRegSet, fs),
            REG_OFFSET(CSGSFS) + sizeof(GRegSet::cs) + sizeof(GRegSet::gs));
  EXPECT_EQ(offsetof(GRegSet, ss), REG_OFFSET(CSGSFS) + sizeof(GRegSet::cs) +
                                       sizeof(GRegSet::gs) +
                                       sizeof(GRegSet::fs));
#undef REG_OFFSET
}

TEST(SignalTest, FPRegOffsets) {
  using signal_fpregset = std::remove_pointer<fpregset_t>::type;
  EXPECT_EQ(offsetof(FPRegSet, fcw), offsetof(signal_fpregset, cwd));
  EXPECT_EQ(offsetof(FPRegSet, fsw), offsetof(signal_fpregset, swd));
  EXPECT_EQ(offsetof(FPRegSet, ftw), offsetof(signal_fpregset, ftw));
  EXPECT_EQ(offsetof(FPRegSet, fop), offsetof(signal_fpregset, fop));
  EXPECT_EQ(offsetof(FPRegSet, rip), offsetof(signal_fpregset, rip));
  EXPECT_EQ(offsetof(FPRegSet, rdp), offsetof(signal_fpregset, rdp));
  EXPECT_EQ(offsetof(FPRegSet, mxcsr), offsetof(signal_fpregset, mxcsr));
  EXPECT_EQ(offsetof(FPRegSet, mxcsr_mask),
            offsetof(signal_fpregset, mxcr_mask));
  EXPECT_EQ(offsetof(FPRegSet, st), offsetof(signal_fpregset, _st));
  EXPECT_EQ(offsetof(FPRegSet, xmm), offsetof(signal_fpregset, _xmm));
}

TEST(SignalTest, ExtraSignalRegs) {
  // Make sure UContext and SaveExtraSignalRegs are initialized differently.
  // This ensures the test doesn't pass because an uninitialized value is the
  // same.

  UContext uc;
  memset(&uc, 0xa5, sizeof(uc));
  SaveUContext(&uc);
  ZeroOutRegsPadding(&uc);

  ExtraSignalRegs eg;
  memset(&eg, 0x5a, sizeof(eg));
  SaveExtraSignalRegs(&eg);

  EXPECT_EQ(uc.gregs.ss, eg.ss);
  EXPECT_EQ(uc.gregs.ds, eg.ds);
  EXPECT_EQ(uc.gregs.es, eg.es);
  EXPECT_EQ(uc.gregs.fs_base, eg.fs_base);
  EXPECT_EQ(uc.gregs.gs_base, eg.gs_base);
}

TEST(SignalTest, ExtraSignalRegsNoSyscalls) {
  // Make sure UContext and SaveExtraSignalRegs are initialized differently.
  // This ensures the test doesn't pass because an uninitialized value is the
  // same.

  UContext uc;
  memset(&uc, 0xa5, sizeof(uc));
  SaveUContextNoSyscalls(&uc);
  ZeroOutRegsPadding(&uc);

  ExtraSignalRegs eg;
  memset(&eg, 0x5a, sizeof(eg));
  SaveExtraSignalRegsNoSyscalls(&eg);

  EXPECT_EQ(uc.gregs.ss, eg.ss);
  EXPECT_EQ(uc.gregs.ds, eg.ds);
  EXPECT_EQ(uc.gregs.es, eg.es);
  EXPECT_EQ(uc.gregs.fs_base, eg.fs_base);
  EXPECT_EQ(uc.gregs.gs_base, eg.gs_base);
}

TEST(SignalTest, ConvertGRegs) {
  ucontext_t libc_ucontext;
  ExtraSignalRegs eg;
  GRegSet gregs;

  pattern_init(&libc_ucontext, sizeof(libc_ucontext), 1000);
  pattern_init(&eg, sizeof(eg), 2000);

  ConvertGRegsFromLibC(libc_ucontext, eg, &gregs);

  const greg_t* lc_gregs = libc_ucontext.uc_mcontext.gregs;

  EXPECT_EQ(lc_gregs[REG_R8], gregs.r8);
  EXPECT_EQ(lc_gregs[REG_R9], gregs.r9);
  EXPECT_EQ(lc_gregs[REG_R10], gregs.r10);
  EXPECT_EQ(lc_gregs[REG_R11], gregs.r11);
  EXPECT_EQ(lc_gregs[REG_R12], gregs.r12);
  EXPECT_EQ(lc_gregs[REG_R13], gregs.r13);
  EXPECT_EQ(lc_gregs[REG_R14], gregs.r14);
  EXPECT_EQ(lc_gregs[REG_R15], gregs.r15);
  EXPECT_EQ(lc_gregs[REG_RDI], gregs.rdi);
  EXPECT_EQ(lc_gregs[REG_RSI], gregs.rsi);
  EXPECT_EQ(lc_gregs[REG_RBP], gregs.rbp);
  EXPECT_EQ(lc_gregs[REG_RBX], gregs.rbx);
  EXPECT_EQ(lc_gregs[REG_RDX], gregs.rdx);
  EXPECT_EQ(lc_gregs[REG_RAX], gregs.rax);
  EXPECT_EQ(lc_gregs[REG_RCX], gregs.rcx);
  EXPECT_EQ(lc_gregs[REG_RSP], gregs.rsp);
  EXPECT_EQ(lc_gregs[REG_RIP], gregs.rip);
  EXPECT_EQ(lc_gregs[REG_EFL], gregs.eflags);

  const uint16_t* selectors =
      reinterpret_cast<const uint16_t*>(&lc_gregs[REG_CSGSFS]);
  EXPECT_EQ(selectors[0], gregs.cs);
  EXPECT_EQ(selectors[1], gregs.gs);
  EXPECT_EQ(selectors[2], gregs.fs);

  EXPECT_EQ(eg.ss, gregs.ss);
  EXPECT_EQ(eg.ds, gregs.ds);
  EXPECT_EQ(eg.es, gregs.es);
  EXPECT_EQ(eg.fs_base, gregs.fs_base);
  EXPECT_EQ(eg.gs_base, gregs.gs_base);
}

// Reads memory at the address `arg`.
extern "C" void UnmappedRead(uint64_t arg);

TEST(SignalTest, UnmappedRead) {
  const uint64_t kBadAddr = 16;
  siginfo_t siginfo;
  ucontext_t uc;
  ExtraSignalRegs extra;
  {
    FatalSignalHandler handler(SIGSEGV);
    ASSERT_TRUE(
        handler.CaptureSignal(UnmappedRead, kBadAddr, &siginfo, &uc, &extra));
  }

  EXPECT_EQ(siginfo.si_signo, SIGSEGV);
  EXPECT_EQ(siginfo.si_addr, (void*)kBadAddr);

  SignalRegSet sigregs;
  ConvertSignalRegsFromLibC(uc, &sigregs);

  EXPECT_EQ(sigregs.err, X86PFError::PF_USER_BIT);
  EXPECT_EQ(siginfo.si_addr, (void*)sigregs.cr2);
  EXPECT_EQ(sigregs.trapno, X86Exception::X86_TRAP_PF);

  // Check the fault is coming from the expected location.
  GRegSet gregs;
  ConvertGRegsFromLibC(uc, extra, &gregs);
  // RIP points at the bad instruction.
  EXPECT_EQ(GetInstructionPointer(gregs),
            reinterpret_cast<uint64_t>(UnmappedRead));
}

// Writes memory at the address `arg`.
extern "C" void UnmappedWrite(uint64_t arg);

TEST(SignalTest, UnmappedWrite) {
  const uint64_t kBadAddr = 24;
  siginfo_t siginfo;
  ucontext_t uc;
  ExtraSignalRegs extra;
  {
    FatalSignalHandler handler(SIGSEGV);
    ASSERT_TRUE(
        handler.CaptureSignal(UnmappedWrite, kBadAddr, &siginfo, &uc, &extra));
  }

  EXPECT_EQ(siginfo.si_signo, SIGSEGV);
  EXPECT_EQ(siginfo.si_addr, (void*)kBadAddr);

  SignalRegSet sigregs;
  ConvertSignalRegsFromLibC(uc, &sigregs);

  EXPECT_EQ(sigregs.err, X86PFError::PF_USER_BIT | X86PFError::PF_WRITE_BIT);
  EXPECT_EQ(siginfo.si_addr, (void*)sigregs.cr2);
  EXPECT_EQ(sigregs.trapno, X86Exception::X86_TRAP_PF);

  // Check the fault is coming from the expected location.
  GRegSet gregs;
  ConvertGRegsFromLibC(uc, extra, &gregs);
  // RIP points at the bad instruction.
  EXPECT_EQ(GetInstructionPointer(gregs),
            reinterpret_cast<uint64_t>(UnmappedWrite));
}

// Executes an illegal instruction.
extern "C" void IllegalInstruction(uint64_t arg);

TEST(SignalTest, IllegalInstruction) {
  siginfo_t siginfo;
  ucontext_t uc;
  ExtraSignalRegs extra;
  {
    FatalSignalHandler handler(SIGILL);
    ASSERT_TRUE(
        handler.CaptureSignal(IllegalInstruction, 0, &siginfo, &uc, &extra));
  }

  EXPECT_EQ(siginfo.si_signo, SIGILL);
  EXPECT_EQ(siginfo.si_code, ILL_ILLOPN);
  EXPECT_EQ(siginfo.si_addr, (void*)IllegalInstruction);

  SignalRegSet sigregs;
  ConvertSignalRegsFromLibC(uc, &sigregs);

  EXPECT_EQ(sigregs.err, 0);

  // Check the fault is coming from the expected location.
  GRegSet gregs;
  ConvertGRegsFromLibC(uc, extra, &gregs);
  // RIP points at the bad instruction.
  EXPECT_EQ(GetInstructionPointer(gregs),
            reinterpret_cast<uint64_t>(IllegalInstruction));
}

// Executes a privileged instruction.
extern "C" void PrivilegedInstruction(uint64_t arg);

TEST(SignalTest, PrivilegedInstruction) {
  siginfo_t siginfo;
  ucontext_t uc;
  ExtraSignalRegs extra;
  {
    FatalSignalHandler handler(SIGSEGV);
    ASSERT_TRUE(
        handler.CaptureSignal(PrivilegedInstruction, 0, &siginfo, &uc, &extra));
  }

  EXPECT_EQ(siginfo.si_signo, SIGSEGV);
  // si_code is 128?
  // The instruction address is not captured here?
  EXPECT_EQ(siginfo.si_addr, (void*)0);

  SignalRegSet sigregs;
  ConvertSignalRegsFromLibC(uc, &sigregs);

  EXPECT_EQ(sigregs.err, 0);

  // Check the fault is coming from the expected location.
  GRegSet gregs;
  ConvertGRegsFromLibC(uc, extra, &gregs);
  // One instruction's worth of setup before the bad instruction.
  EXPECT_EQ(GetInstructionPointer(gregs),
            reinterpret_cast<uint64_t>(PrivilegedInstruction) + 5);
}

// Executes a debug breakpoint instruction.
extern "C" void DebugInstruction(uint64_t arg);

TEST(SignalTest, DebugInstruction) {
  siginfo_t siginfo;
  ucontext_t uc;
  ExtraSignalRegs extra;
  {
    FatalSignalHandler handler(SIGTRAP);
    ASSERT_TRUE(
        handler.CaptureSignal(DebugInstruction, 0, &siginfo, &uc, &extra));
  }

  EXPECT_EQ(siginfo.si_signo, SIGTRAP);
  // si_code is 128?
  // The instruction address is not captured here?
  EXPECT_EQ(siginfo.si_addr, (void*)0);

  SignalRegSet sigregs;
  ConvertSignalRegsFromLibC(uc, &sigregs);

  EXPECT_EQ(sigregs.err, 0);

  // Check the fault is coming from the expected location.
  GRegSet gregs;
  ConvertGRegsFromLibC(uc, extra, &gregs);
  // RIP points _after_ the trap instruction.
  EXPECT_EQ(GetInstructionPointer(gregs),
            reinterpret_cast<uint64_t>(DebugInstruction) + 1);
}

}  // namespace
}  // namespace silifuzz
