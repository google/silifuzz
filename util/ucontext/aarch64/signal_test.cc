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

#include <signal.h>

#include "gtest/gtest.h"
#include "./util/ucontext/aarch64/esr.h"
#include "./util/ucontext/signal.h"
#include "./util/ucontext/ucontext.h"

namespace silifuzz {
namespace {

void pattern_init(void* data, size_t size, size_t seed) {
  uint16_t* ptr = reinterpret_cast<uint16_t*>(data);
  for (int i = 0; i < size / sizeof(*ptr); ++i) {
    ptr[i] = (uint16_t)(seed + i) * 63073;
  }
}

TEST(SignalTest, ExtraSignalRegs) {
  // Make sure UContext and SaveExtraSignalRegs are initialized differently.
  // This ensures the test doesn't pass because an uninitialized value is the
  // same.

  UContext<AArch64> uc;
  memset(&uc, 0xa5, sizeof(uc));
  SaveUContext(&uc);
  ZeroOutRegsPadding(&uc);

  ExtraSignalRegs eg;
  memset(&eg, 0x5a, sizeof(eg));
  SaveExtraSignalRegs(&eg);

  EXPECT_EQ(uc.gregs.tpidr, eg.tpidr);
  EXPECT_EQ(uc.gregs.tpidrro, eg.tpidrro);
}

TEST(SignalTest, ExtraSignalRegsNoSyscalls) {
  // Make sure UContext and SaveExtraSignalRegs are initialized differently.
  // This ensures the test doesn't pass because an uninitialized value is the
  // same.

  UContext<AArch64> uc;
  memset(&uc, 0xa5, sizeof(uc));
  SaveUContextNoSyscalls(&uc);
  ZeroOutRegsPadding(&uc);

  ExtraSignalRegs eg;
  memset(&eg, 0x5a, sizeof(eg));
  SaveExtraSignalRegsNoSyscalls(&eg);

  EXPECT_EQ(uc.gregs.tpidr, eg.tpidr);
  EXPECT_EQ(uc.gregs.tpidrro, eg.tpidrro);
}

TEST(SignalTest, ConvertGRegs) {
  ucontext_t libc_ucontext;
  ExtraSignalRegs eg;
  GRegSet<AArch64> gregs;

  pattern_init(&libc_ucontext, sizeof(libc_ucontext), 1000);
  pattern_init(&eg, sizeof(eg), 2000);

  ConvertGRegsFromLibC(libc_ucontext, eg, &gregs);

  mcontext_t ctx = libc_ucontext.uc_mcontext;
  for (int i = 0; i < 31; ++i) {
    EXPECT_EQ(gregs.x[i], ctx.regs[i]);
  }
  EXPECT_EQ(gregs.sp, ctx.sp);
  EXPECT_EQ(gregs.pc, ctx.pc);
  EXPECT_EQ(gregs.pstate, ctx.pstate);

  EXPECT_EQ(gregs.tpidr, eg.tpidr);
  EXPECT_EQ(gregs.tpidrro, eg.tpidrro);
}

// The is a helper class to install and trigger a signal handler to we can test
// the code's ability to parse an actual context created by the system.
// This is a class so that the destructor will clean up the action handler.
class TestSignalHandler {
 public:
  TestSignalHandler() {
    struct sigaction action = {};
    action.sa_sigaction = SigAction;
    action.sa_flags = SA_SIGINFO | SA_NODEFER;
    old_ = {};
    EXPECT_EQ(sigaction(SIGUSR1, &action, &old_), 0);
  }

  ~TestSignalHandler() { EXPECT_EQ(sigaction(SIGUSR1, &old_, nullptr), 0); }

  void capture_context(ucontext_t* uc) {
    memset(uc, 0xc3, sizeof(*uc));
    current_capture = uc;
    EXPECT_EQ(raise(SIGUSR1), 0);
    current_capture = nullptr;
  }

 private:
  static void SigAction(int signal, siginfo_t* siginfo, void* uc) {
    *current_capture = *reinterpret_cast<ucontext_t*>(uc);
  }

  // The sigaction handler does not have a user context, so we need to use a
  // global to dump the result of the action handler in a place the test can
  // find it.
  static ucontext_t* current_capture;

  struct sigaction old_;
};

ucontext_t* TestSignalHandler::current_capture;

void capture_context(ucontext_t* ctx) {
  TestSignalHandler handler;
  handler.capture_context(ctx);
}

TEST(SignalTest, HandlerWorksAsExpected) {
  ucontext_t ctx;
  capture_context(&ctx);

  // Make sure we can interpret a FP context provided by the system. This
  // involves chasing a few pointers and isn't completely trivial. Although we
  // can't say much about the correctness of the values we recive, we can at
  // least make sure we interpret an actual context without crashing or
  // detecting inconsistencies.
  FPRegSet<AArch64> fpregs;
  ConvertFPRegsFromLibC(ctx, &fpregs);

  // Capture the current context.
  UContext<AArch64> uc;
  memset(&uc, 0xf0, sizeof(uc));
  SaveUContext(&uc);
  ZeroOutRegsPadding(&uc);

  // The floating point control register is likely the same?
  // Everything else is too volatile to rely on.
  EXPECT_EQ(uc.fpregs.fpcr, fpregs.fpcr);
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
  EXPECT_EQ(siginfo.si_code, SEGV_MAPERR);
  EXPECT_EQ(siginfo.si_addr, (void*)kBadAddr);
  EXPECT_EQ(siginfo.si_addr, (void*)uc.uc_mcontext.fault_address);

  SignalRegSet sigregs;
  ConvertSignalRegsFromLibC(uc, &sigregs);
  ESR esr = {sigregs.esr};

  // Data Abort from a lower Exception level.
  EXPECT_TRUE(esr.IsDataAbort());
  EXPECT_EQ(esr.ExceptionClass(), ExceptionClass::kDataAbortLowerLevel);

  // 32-bit instruction, this isn't THUMB.
  EXPECT_TRUE(esr.InstructionLength());

  DataAbortISS iss = esr.GetDataAbortISS();
  EXPECT_FALSE(iss.FARNotValid());

  // This is not a write.
  EXPECT_FALSE(iss.WriteNotRead());

  // Check the fault is coming from the expected location.
  GRegSet<AArch64> gregs;
  ConvertGRegsFromLibC(uc, extra, &gregs);
  EXPECT_EQ(gregs.GetInstructionPointer(),
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
  EXPECT_EQ(siginfo.si_code, SEGV_MAPERR);
  EXPECT_EQ(siginfo.si_addr, (void*)kBadAddr);
  EXPECT_EQ(siginfo.si_addr, (void*)uc.uc_mcontext.fault_address);

  SignalRegSet sigregs;
  ConvertSignalRegsFromLibC(uc, &sigregs);
  ESR esr = {sigregs.esr};

  // Data Abort from a lower Exception level.
  EXPECT_TRUE(esr.IsDataAbort());
  EXPECT_EQ(esr.ExceptionClass(), ExceptionClass::kDataAbortLowerLevel);

  // 32-bit instruction, this isn't THUMB.
  EXPECT_TRUE(esr.InstructionLength());

  DataAbortISS iss = esr.GetDataAbortISS();
  EXPECT_FALSE(iss.FARNotValid());

  // This is a write.
  EXPECT_TRUE(iss.WriteNotRead());

  // Check the fault is coming from the expected location.
  GRegSet<AArch64> gregs;
  ConvertGRegsFromLibC(uc, extra, &gregs);
  EXPECT_EQ(gregs.GetInstructionPointer(),
            reinterpret_cast<uint64_t>(UnmappedWrite));
}

TEST(SignalTest, UnmappedExecute) {
  const uint64_t kBadAddr = 32;
  siginfo_t siginfo;
  ucontext_t uc;
  ExtraSignalRegs extra;
  {
    FatalSignalHandler handler(SIGSEGV);
    ASSERT_TRUE(handler.CaptureSignal(reinterpret_cast<TestFunc>(kBadAddr), 0,
                                      &siginfo, &uc, &extra));
  }

  EXPECT_EQ(siginfo.si_signo, SIGSEGV);
  EXPECT_EQ(siginfo.si_code, SEGV_MAPERR);
  EXPECT_EQ(siginfo.si_addr, (void*)kBadAddr);
  EXPECT_EQ(siginfo.si_addr, (void*)uc.uc_mcontext.fault_address);

  SignalRegSet sigregs;
  ConvertSignalRegsFromLibC(uc, &sigregs);
  ESR esr = {sigregs.esr};

  // Instruction Abort from a lower Exception level.
  EXPECT_TRUE(esr.IsInstructionAbort());
  EXPECT_EQ(esr.ExceptionClass(), ExceptionClass::kInstructionAbortLowerLevel);

  // 32-bit instruction, this isn't THUMB.
  EXPECT_TRUE(esr.InstructionLength());

  InstructionAbortISS iss = esr.GetInstructionAbortISS();
  EXPECT_FALSE(iss.FARNotValid());

  // Check the fault is coming from the expected location.
  GRegSet<AArch64> gregs;
  ConvertGRegsFromLibC(uc, extra, &gregs);
  EXPECT_EQ(gregs.GetInstructionPointer(),
            reinterpret_cast<uint64_t>(kBadAddr));
}

TEST(SignalTest, UnalignedExecute) {
  TestFunc unaligned_func =
      reinterpret_cast<TestFunc>(reinterpret_cast<uint64_t>(UnmappedWrite) + 1);
  siginfo_t siginfo;
  ucontext_t uc;
  ExtraSignalRegs extra;
  {
    FatalSignalHandler handler(SIGBUS);
    ASSERT_TRUE(
        handler.CaptureSignal(unaligned_func, 0, &siginfo, &uc, &extra));
  }

  EXPECT_EQ(siginfo.si_signo, SIGBUS);
  EXPECT_EQ(siginfo.si_code, BUS_ADRALN);
  EXPECT_EQ(siginfo.si_addr, (void*)unaligned_func);
  EXPECT_EQ(uc.uc_mcontext.fault_address, 0);

  SignalRegSet sigregs;
  ConvertSignalRegsFromLibC(uc, &sigregs);
  ESR esr = {sigregs.esr};

  // PC alignment fault exception.
  EXPECT_TRUE(esr.IsPCAlignmentFault());

  // 32-bit instruction, this isn't THUMB.
  EXPECT_TRUE(esr.InstructionLength());

  // Check the fault is coming from the expected location.
  GRegSet<AArch64> gregs;
  ConvertGRegsFromLibC(uc, extra, &gregs);
  EXPECT_EQ(gregs.GetInstructionPointer(),
            reinterpret_cast<uint64_t>(unaligned_func));
}

TEST(SignalTest, Unexecutable) {
  // A return instruction, so if this somehow executes the test continues
  // without throwing a signal.
  uint32_t ret_inst = 0xd65f03c0;
  TestFunc unexecutable_func = reinterpret_cast<TestFunc>(&ret_inst);

  siginfo_t siginfo;
  ucontext_t uc;
  ExtraSignalRegs extra;
  {
    FatalSignalHandler handler(SIGSEGV);
    ASSERT_TRUE(
        handler.CaptureSignal(unexecutable_func, 0, &siginfo, &uc, &extra));
  }

  EXPECT_EQ(siginfo.si_signo, SIGSEGV);
  EXPECT_EQ(siginfo.si_code, SEGV_ACCERR);
  EXPECT_EQ(siginfo.si_addr, (void*)unexecutable_func);
  EXPECT_EQ(siginfo.si_addr, (void*)uc.uc_mcontext.fault_address);

  SignalRegSet sigregs;
  ConvertSignalRegsFromLibC(uc, &sigregs);
  ESR esr = {sigregs.esr};

  // Instruction Abort from a lower Exception level.
  EXPECT_TRUE(esr.IsInstructionAbort());
  EXPECT_EQ(esr.ExceptionClass(), ExceptionClass::kInstructionAbortLowerLevel);

  // 32-bit instruction, this isn't THUMB.
  EXPECT_TRUE(esr.InstructionLength());

  InstructionAbortISS iss = esr.GetInstructionAbortISS();
  EXPECT_FALSE(iss.FARNotValid());

  // Check the fault is coming from the expected location.
  GRegSet<AArch64> gregs;
  ConvertGRegsFromLibC(uc, extra, &gregs);
  EXPECT_EQ(gregs.GetInstructionPointer(),
            reinterpret_cast<uint64_t>(unexecutable_func));
}

// Intentionally misaligns the stack.
extern "C" void UnalignedStack(uint64_t arg);

TEST(SignalTest, UnalignedStack) {
  siginfo_t siginfo;
  ucontext_t uc;
  ExtraSignalRegs extra;
  {
    FatalSignalHandler handler(SIGBUS);
    ASSERT_TRUE(
        handler.CaptureSignal(UnalignedStack, 1, &siginfo, &uc, &extra));
  }

  EXPECT_EQ(siginfo.si_signo, SIGBUS);
  EXPECT_EQ(siginfo.si_code, BUS_ADRALN);
  EXPECT_EQ(siginfo.si_addr, (void*)uc.uc_mcontext.sp);
  EXPECT_EQ(uc.uc_mcontext.fault_address, 0);

  SignalRegSet sigregs;
  ConvertSignalRegsFromLibC(uc, &sigregs);
  ESR esr = {sigregs.esr};

  // SP alignment fault exception.
  EXPECT_TRUE(esr.IsSPAlignmentFault());

  // 32-bit instruction, this isn't THUMB.
  EXPECT_TRUE(esr.InstructionLength());

  // Check the fault is coming from the expected location.
  GRegSet<AArch64> gregs;
  ConvertGRegsFromLibC(uc, extra, &gregs);
  // One instruction of setup before the fault.
  // Stack alignment issues are detected on use.
  EXPECT_EQ(gregs.GetInstructionPointer(),
            reinterpret_cast<uint64_t>(UnalignedStack) + 4);
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
  EXPECT_EQ(siginfo.si_code, ILL_ILLOPC);
  EXPECT_EQ(siginfo.si_addr, (void*)IllegalInstruction);
  EXPECT_EQ(uc.uc_mcontext.fault_address, 0);

  SignalRegSet sigregs;
  ConvertSignalRegsFromLibC(uc, &sigregs);
  ESR esr = {sigregs.esr};

  // No ESR for illegal instruction.
  EXPECT_TRUE(esr.IsUnknown());

  // Check the fault is coming from the expected location.
  GRegSet<AArch64> gregs;
  ConvertGRegsFromLibC(uc, extra, &gregs);
  // PC points at the bad instruction.
  EXPECT_EQ(gregs.GetInstructionPointer(),
            reinterpret_cast<uint64_t>(IllegalInstruction));
}

// Executes a privileged instruction.
extern "C" void PrivilegedInstruction(uint64_t arg);

TEST(SignalTest, PrivilegedInstruction) {
  siginfo_t siginfo;
  ucontext_t uc;
  ExtraSignalRegs extra;
  {
    FatalSignalHandler handler(SIGILL);
    ASSERT_TRUE(
        handler.CaptureSignal(PrivilegedInstruction, 0, &siginfo, &uc, &extra));
  }

  EXPECT_EQ(siginfo.si_signo, SIGILL);
  EXPECT_EQ(siginfo.si_code, ILL_ILLOPC);  // Not ILL_PRVOPC, for some reason?
  EXPECT_EQ(siginfo.si_addr, (void*)PrivilegedInstruction);
  EXPECT_EQ(uc.uc_mcontext.fault_address, 0);

  SignalRegSet sigregs;
  ConvertSignalRegsFromLibC(uc, &sigregs);
  ESR esr = {sigregs.esr};

  // No ESR for illegal instruction.
  EXPECT_TRUE(esr.IsUnknown());

  // Check the fault is coming from the expected location.
  GRegSet<AArch64> gregs;
  ConvertGRegsFromLibC(uc, extra, &gregs);
  // PC points at the bad instruction.
  EXPECT_EQ(gregs.GetInstructionPointer(),
            reinterpret_cast<uint64_t>(PrivilegedInstruction));
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
  EXPECT_EQ(siginfo.si_code, TRAP_BRKPT);
  EXPECT_EQ(siginfo.si_addr, (void*)DebugInstruction);
  EXPECT_EQ(uc.uc_mcontext.fault_address, 0);

  SignalRegSet sigregs;
  ConvertSignalRegsFromLibC(uc, &sigregs);
  ESR esr = {sigregs.esr};

  // No ESR for debug instruction.
  EXPECT_TRUE(esr.IsUnknown());

  // Check the fault is coming from the expected location.
  GRegSet<AArch64> gregs;
  ConvertGRegsFromLibC(uc, extra, &gregs);
  // PC points _at_ the debug instruction.
  EXPECT_EQ(gregs.GetInstructionPointer(),
            reinterpret_cast<uint64_t>(DebugInstruction));
}

TEST(SignalTest, ConvertFPRegs) {
  ucontext_t libc_ucontext;
  FPRegSet<AArch64> fpregs;

  pattern_init(&libc_ucontext, sizeof(libc_ucontext), 1000);

  // Modify the random pattern to appear like a valid list of contexts.
  fpsimd_context* fpc =
      reinterpret_cast<fpsimd_context*>(libc_ucontext.uc_mcontext.__reserved);
  fpc->head.magic = FPSIMD_MAGIC;
  fpc->head.size = sizeof(*fpc);

  // Terminate the list.
  _aarch64_ctx* terminator = reinterpret_cast<_aarch64_ctx*>(
      libc_ucontext.uc_mcontext.__reserved + sizeof(*fpc));
  terminator->magic = 0;
  terminator->size = 0;

  // Extract the FP context.
  ConvertFPRegsFromLibC(libc_ucontext, &fpregs);

  // Check that the values have been copied over correctly.
  for (int i = 0; i < 32; ++i) {
    EXPECT_EQ(fpregs.v[i], fpc->vregs[i]);
  }
  EXPECT_EQ(fpregs.fpsr, fpc->fpsr);
  EXPECT_EQ(fpregs.fpcr, fpc->fpcr);
}

}  // namespace
}  // namespace silifuzz
