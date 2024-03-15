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

#include "./util/ucontext/ucontext.h"

#include <stdint.h>

#include <cstddef>
#include <cstring>
#include <string>

#include "gtest/gtest.h"
#include "./util/arch.h"
#include "./util/arch_mem.h"
#include "./util/checks.h"
#include "./util/logging_util.h"
#include "./util/ucontext/ucontext_types.h"
#include "./util/ucontext/x86_64/ucontext_offsets.h"
#include "./util/ucontext/x86_64/ucontext_test_lib.h"

#ifdef UCONTEXT_NO_SYSCALLS
#define SAVE_UCONTEXT SaveUContextNoSyscalls
#define RESTORE_UCONTEXT RestoreUContextNoSyscalls
#else
#define SAVE_UCONTEXT SaveUContext
#define RESTORE_UCONTEXT RestoreUContext
#endif

// Hack for working around quirks of inline asm.
#define STR_INNER(x) #x
#define STR(x) STR_INNER(x)

namespace silifuzz {
namespace {

TEST(UContextTest, Accessors) {
  UContext<X86_64> uc;
  memset(&uc, 0xf0, sizeof(uc));

  constexpr uint64_t kInstructionPointer = 0x0123456789abcdef;
  constexpr uint64_t kStackPointer = 0xfedcba9876543210;
  uc.gregs.SetInstructionPointer(kInstructionPointer);
  uc.gregs.SetStackPointer(kStackPointer);

  EXPECT_EQ(uc.gregs.GetInstructionPointer(), kInstructionPointer);
  EXPECT_EQ(uc.gregs.rip, kInstructionPointer);

  EXPECT_EQ(uc.gregs.GetStackPointer(), kStackPointer);
  EXPECT_EQ(uc.gregs.rsp, kStackPointer);
}

// Check that UContext introduces no padding, and hence the ZeroOutRegsPadding()
// helper is easy to write.
TEST(UContextTypes, NoGaps) {
  // Check that there are no gaps in GRegSet:
  EXPECT_EQ(
      sizeof(GRegSet<X86_64>),
      sizeof(uint64_t) * (8 /* r8 .. r15*/ + 9 /* named regs */) +
          sizeof(uint64_t) /* eflags */ + sizeof(uint16_t) * 6 /* cs .. es */ +
          sizeof(uint64_t) * 2 /* fs_base, gs_base */ +
          sizeof(uint32_t) /* padding */
  );
  // FPRegSet must be exactly 512 for fxsave/fxrestor.
  EXPECT_EQ(sizeof(FPRegSet<X86_64>), 512) << "FPRegSet has unexpected size.";

  // Check that there are no gaps in UContext:
  EXPECT_EQ(offsetof(UContext<X86_64>, fpregs), 0);
  EXPECT_EQ(offsetof(UContext<X86_64>, gregs), sizeof(FPRegSet<X86_64>));
  EXPECT_EQ(sizeof(UContext<X86_64>),
            sizeof(FPRegSet<X86_64>) + sizeof(GRegSet<X86_64>));
}

// Verify that the constants from ucontext_offsets.h are as expected.
// All these can be done as static_assert, but gunit checks log better
// diagnostics if the constants do not match.
TEST(UContextTest, Constants) {
  EXPECT_EQ(UCONTEXT_FPREGS_OFFSET, offsetof(UContext<X86_64>, fpregs));
  EXPECT_EQ(UCONTEXT_GREGS_OFFSET, offsetof(UContext<X86_64>, gregs));
  EXPECT_EQ(GREGS_R8_OFFSET, offsetof(GRegSet<X86_64>, r8));
  EXPECT_EQ(GREGS_R9_OFFSET, offsetof(GRegSet<X86_64>, r9));
  EXPECT_EQ(GREGS_R10_OFFSET, offsetof(GRegSet<X86_64>, r10));
  EXPECT_EQ(GREGS_R11_OFFSET, offsetof(GRegSet<X86_64>, r11));
  EXPECT_EQ(GREGS_R12_OFFSET, offsetof(GRegSet<X86_64>, r12));
  EXPECT_EQ(GREGS_R13_OFFSET, offsetof(GRegSet<X86_64>, r13));
  EXPECT_EQ(GREGS_R14_OFFSET, offsetof(GRegSet<X86_64>, r14));
  EXPECT_EQ(GREGS_R15_OFFSET, offsetof(GRegSet<X86_64>, r15));
  EXPECT_EQ(GREGS_RDI_OFFSET, offsetof(GRegSet<X86_64>, rdi));
  EXPECT_EQ(GREGS_RSI_OFFSET, offsetof(GRegSet<X86_64>, rsi));
  EXPECT_EQ(GREGS_RBP_OFFSET, offsetof(GRegSet<X86_64>, rbp));
  EXPECT_EQ(GREGS_RBX_OFFSET, offsetof(GRegSet<X86_64>, rbx));
  EXPECT_EQ(GREGS_RDX_OFFSET, offsetof(GRegSet<X86_64>, rdx));
  EXPECT_EQ(GREGS_RAX_OFFSET, offsetof(GRegSet<X86_64>, rax));
  EXPECT_EQ(GREGS_RCX_OFFSET, offsetof(GRegSet<X86_64>, rcx));
  EXPECT_EQ(GREGS_RSP_OFFSET, offsetof(GRegSet<X86_64>, rsp));
  EXPECT_EQ(GREGS_RIP_OFFSET, offsetof(GRegSet<X86_64>, rip));
  EXPECT_EQ(GREGS_EFLAGS_OFFSET, offsetof(GRegSet<X86_64>, eflags));
  EXPECT_EQ(GREGS_CS_OFFSET, offsetof(GRegSet<X86_64>, cs));
  EXPECT_EQ(GREGS_GS_OFFSET, offsetof(GRegSet<X86_64>, gs));
  EXPECT_EQ(GREGS_FS_OFFSET, offsetof(GRegSet<X86_64>, fs));
  EXPECT_EQ(GREGS_SS_OFFSET, offsetof(GRegSet<X86_64>, ss));
  EXPECT_EQ(GREGS_DS_OFFSET, offsetof(GRegSet<X86_64>, ds));
  EXPECT_EQ(GREGS_ES_OFFSET, offsetof(GRegSet<X86_64>, es));
  EXPECT_EQ(GREGS_FS_BASE_OFFSET, offsetof(GRegSet<X86_64>, fs_base));
  EXPECT_EQ(GREGS_GS_BASE_OFFSET, offsetof(GRegSet<X86_64>, gs_base));
}

// This tests that ZeroOutRegsPadding() and SaveUContext() together fill
// all bytes of gregs and fpregs.
//
// The per-register tests for SaveUContext() will test that
// ZeroOutRegsPadding() does not 0-out things that SaveUContext() fills.
//
// Same happens in these tests for ZeroOutSigmaskPadding() and the sigmask
// bytes.
TEST(UContextTest, Padding) {
  // Each of ucX will be created slightly differently but the register
  // and sigmask values in them must match.
  UContext<X86_64>
      uc1;  // 0xAB-init, zero-out, SaveUContext(), FixUpRegsPadding()
  UContext<X86_64> uc2;  // 0xCD-init, SaveUContext(), zero-out
  UContext<X86_64>
      uc3;  // 0-init, sigemptyset(), SaveUContext(), FixUpRegsPadding()
  UContext<X86_64> uc4;  // SaveUContext(), zero-out

  memset(&uc1, 0xAB, sizeof(uc1));
  memset(&uc2, 0xCD, sizeof(uc2));
  memset(&uc3, 0, sizeof(uc3));

  ZeroOutRegsPadding(&uc1);
  UContext<X86_64>* ucs[] = {&uc1, &uc2, &uc3, &uc4};
  // Use inline asm to ensure the four SaveUContext(ucs[i]) calls
  // are back-to-back and no callee-saved register can be altered.
  // Note: the clobber list depends on SaveUContext not modifying any registers.
  asm("movq 0(%%rbx), %%rdi\n"
      "call " STR(SAVE_UCONTEXT) "\n"
      "movq 8(%%rbx), %%rdi\n"
      "call " STR(SAVE_UCONTEXT) "\n"
      "movq 16(%%rbx), %%rdi\n"
      "call " STR(SAVE_UCONTEXT) "\n"
      "movq 24(%%rbx), %%rdi\n"
      "call " STR(SAVE_UCONTEXT) "\n" ::"b"(ucs)
      : "rdi", "memory");
  ZeroOutRegsPadding(&uc2);
  ZeroOutRegsPadding(&uc4);
  // Have to do these after SaveUContext():
  FixUpRegsPadding(&uc1);
  FixUpRegsPadding(&uc2);
  FixUpRegsPadding(&uc3);

  EXPECT_TRUE(HasZeroRegsPadding(uc1));
  EXPECT_TRUE(HasZeroRegsPadding(uc2));
  EXPECT_TRUE(HasZeroRegsPadding(uc3));
  EXPECT_TRUE(HasZeroRegsPadding(uc4));

  // Exercise HasCurrentSegmentRegisters() a little;
  // The other TEST(UContextTest, ...) below exercise it more.
  EXPECT_TRUE(HasCurrentSegmentRegisters(uc1));
  EXPECT_TRUE(HasCurrentSegmentRegisters(uc2));
  EXPECT_TRUE(HasCurrentSegmentRegisters(uc3));
  EXPECT_TRUE(HasCurrentSegmentRegisters(uc4));

#if !defined(UCONTEXT_NO_SYSCALLS)
  // FS_BASE is used for TLS so shouldn't be 0
  EXPECT_NE(uc1.gregs.fs_base, 0);
  EXPECT_NE(uc2.gregs.fs_base, 0);
  EXPECT_NE(uc3.gregs.fs_base, 0);
  EXPECT_NE(uc4.gregs.fs_base, 0);
  // GS_BASE is typically 0 on Linux but this a not strict requirement, just
  // something we test to verify that SaveUContext() wrote something into
  // gs_base.
  EXPECT_EQ(uc1.gregs.gs_base, 0);
  EXPECT_EQ(uc2.gregs.gs_base, 0);
  EXPECT_EQ(uc3.gregs.gs_base, 0);
  EXPECT_EQ(uc4.gregs.gs_base, 0);
#endif

  // rip and rdi values (but nothing else) are expected to be different.
  uc2.gregs.rip = uc1.gregs.rip;
  uc3.gregs.rip = uc1.gregs.rip;
  uc4.gregs.rip = uc1.gregs.rip;
  uc2.gregs.rdi = uc1.gregs.rdi;
  uc3.gregs.rdi = uc1.gregs.rdi;
  uc4.gregs.rdi = uc1.gregs.rdi;

  if (DEBUG_MODE) {  // Only to help debugging EXPECT_TRUE-s below.
    LOG_INFO("uc4.gregs vs uc1:");
    LogGRegs(uc4.gregs, &uc1.gregs, true);
    LOG_INFO("uc4.fpregs vs uc1:");
    LogFPRegs(uc4.fpregs, true, &uc1.fpregs, true);
  }
  EXPECT_TRUE(uc1.gregs == uc2.gregs);
  EXPECT_TRUE(uc1.gregs == uc3.gregs);
  EXPECT_TRUE(uc1.gregs == uc4.gregs);
  EXPECT_TRUE(uc1.fpregs == uc2.fpregs);
  EXPECT_TRUE(uc1.fpregs == uc3.fpregs);
  EXPECT_TRUE(uc1.fpregs == uc4.fpregs);
}

// Test saving and restoring of each of general-purpose registers,
// except for rsp and rip,
//
// This primarily tests SaveUContext() and RestoreUContext(),
// but also exercises and thus tests CurrentInstructionPointer(),
// ZeroOutRegsPadding(), HasCurrentSegmentRegisters().
TEST(UContextTest, SimpleRegisters) {
  test_reg_value = 0x123456789a;

  TestOneRegister_r8();
  TestOneRegister_r9();
  TestOneRegister_r10();
  TestOneRegister_r11();
  TestOneRegister_r12();
  TestOneRegister_r13();
  TestOneRegister_r14();
  TestOneRegister_r15();

  // Some sanitizer-inserted code interferes for a couple of registers:
#if !defined(THREAD_SANITIZER)
  TestOneRegister_rdi();
#endif
  TestOneRegister_rsi();
  TestOneRegister_rbx();
  TestOneRegister_rdx();
#if !defined(THREAD_SANITIZER) && !defined(MEMORY_SANITIZER)
  TestOneRegister_rbp();
#endif
#if !defined(THREAD_SANITIZER) && !defined(MEMORY_SANITIZER) && \
    !defined(ADDRESS_SANITIZER)
  TestOneRegister_rax();
#endif
#if !defined(MEMORY_SANITIZER) && !defined(ADDRESS_SANITIZER)
  TestOneRegister_rcx();
#endif
}

// Tests saving and restoring for rsp and rip registers
// -- testng logic is special-cased for these.
TEST(UContextTest, SpecialRegisters) { TestSpecialRegisters_rsp_rip(); }

// Tests saving and restoring for segment registers, eflags, and fp registers.
TEST(UContextTest, AllOtherFields) { TestUContextVarious(); }

#define TestOneSegmentRegister(name)                         \
  do {                                                       \
    GRegSet<X86_64> expected = actual;                       \
    expected.name = 1000;                                    \
    EXPECT_FALSE(HasSameSegmentRegisters(actual, expected)); \
  } while (0)
TEST(UContextTest, HasSameSegmentRegisters) {
  GRegSet<X86_64> actual = {
      .cs = 1, .gs = 2, .fs = 3, .ss = 4, .ds = 5, .es = 6};
  EXPECT_TRUE(CriticalUnrestoredRegistersAreSame(actual, actual));
  TestOneSegmentRegister(cs);
  TestOneSegmentRegister(gs);
  TestOneSegmentRegister(fs);
  TestOneSegmentRegister(ss);
  TestOneSegmentRegister(ds);
  TestOneSegmentRegister(es);
}

constexpr size_t kStackSize = 512;
// Reserve a little space after the stack pointer so we can detect bad writes.
constexpr size_t kStackOffset = kStackSize - 64;
constexpr uint8_t kStackPattern = 0xe1;

void PatternInitStack(uint8_t* stack) {
  memset(stack, kStackPattern, kStackSize);
}

void CheckEntryStackBytes(const GRegSet<X86_64>& gregs, const uint8_t* stack) {
  // Synthesize the expected state of the stack RestoreUContext() switches to.
  uint8_t expected[kStackSize];
  PatternInitStack(expected);

  std::string stack_bytes = RestoreUContextStackBytes(gregs);
  memcpy(expected + kStackOffset - stack_bytes.size(), stack_bytes.data(),
         stack_bytes.size());

  // Compare.
  for (size_t i = 0; i < kStackSize; i++) {
    EXPECT_EQ(stack[i], expected[i]) << i;
  }
}

void CheckExitStackBytes(const GRegSet<X86_64>& gregs, const uint8_t* stack) {
  // The stack usage of x86_64 RestoreUContext is hard to predict because it
  // calls into C to check for the existence of AVX512 registers. Emperically,
  // x86_64 RestoreUContext() uses ~152 bytes of stack at the time of writing.
  // Because part of that is calling into C code, we can't be 100% sure this
  // won't shift, so be conservative about how much we expect will be clobbered.
  constexpr size_t stack_bytes_used = 168;
  ASSERT_GE(kStackOffset, stack_bytes_used);

  for (size_t i = 0; i < kStackOffset - stack_bytes_used; i++) {
    EXPECT_EQ(stack[i], kStackPattern) << i;
  }

  // The exit bytes should not be leaking into snapshots, so we care less about
  // the exact values than the entry bytes. We still care how much space is
  // used, however.

  for (size_t i = kStackOffset; i < kStackSize; i++) {
    EXPECT_EQ(stack[i], kStackPattern) << i;
  }
}

extern "C" void CaptureStack(silifuzz::UContext<silifuzz::X86_64>* uc,
                             void* alternate_stack);

// TODO(ncbray): figure out why RestoreUContextNoSyscalls smashing TLS causes
// problems for this particular test.
#if !defined(UCONTEXT_NO_SYSCALLS)

TEST(UContextTest, RestoreUContextStackBytes) {
  UContext<X86_64> test, saved;

  alignas(16) uint8_t entry_stack[kStackSize];
  PatternInitStack(entry_stack);

  alignas(16) uint8_t exit_stack[kStackSize];
  PatternInitStack(exit_stack);

  // Start with the existing context so we can keep TLS intact, etc.
  SAVE_UCONTEXT(&test);
  ZeroOutRegsPadding(&test);

  // Set up to restore the context into a call to CaptureStack
  test.gregs.rip = reinterpret_cast<uint64_t>(&CaptureStack);
  test.gregs.rdi = reinterpret_cast<uint64_t>(&saved);
  test.gregs.rsi = reinterpret_cast<uint64_t>(&exit_stack[kStackOffset]);
  test.gregs.rsp = reinterpret_cast<uint64_t>(&entry_stack[kStackOffset]);

  // Execute the CaptureStack function.
  volatile unsigned int post_save_count = 0;
  SAVE_UCONTEXT(&saved);
  post_save_count++;
  ASSERT_LE(post_save_count, 2);
  if (post_save_count == 1) {
    // We just saved the current context.
    RESTORE_UCONTEXT(&test);
    __builtin_unreachable();
  }
  // We have returned from the restore.
  ASSERT_EQ(post_save_count, 2);

  // Make MSAN happy.
  ZeroOutRegsPadding(&saved);

  // This function => RestoreUContext(test) => CaptureStack
  CheckEntryStackBytes(test.gregs, entry_stack);

  // CaptureStack => RestoreUContext(saved) => this function
  CheckExitStackBytes(saved.gregs, exit_stack);
}

#endif

}  // namespace
}  // namespace silifuzz
