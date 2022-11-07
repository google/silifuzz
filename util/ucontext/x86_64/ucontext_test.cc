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

#include "gtest/gtest.h"
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
  SetInstructionPointer(uc.gregs, kInstructionPointer);
  SetStackPointer(uc.gregs, kStackPointer);

  EXPECT_EQ(GetInstructionPointer(uc.gregs), kInstructionPointer);
  EXPECT_EQ(uc.gregs.rip, kInstructionPointer);

  EXPECT_EQ(GetStackPointer(uc.gregs), kStackPointer);
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

  // FPRegSet is defined in libc to match fxsave64/fxrstor64, so no
  // need to check for gaps in that.

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
  EXPECT_EQ(UCONTEXT_GREGS_R8_OFFSET, offsetof(UContext<X86_64>, gregs.r8));
  EXPECT_EQ(UCONTEXT_GREGS_R9_OFFSET, offsetof(UContext<X86_64>, gregs.r9));
  EXPECT_EQ(UCONTEXT_GREGS_R10_OFFSET, offsetof(UContext<X86_64>, gregs.r10));
  EXPECT_EQ(UCONTEXT_GREGS_R11_OFFSET, offsetof(UContext<X86_64>, gregs.r11));
  EXPECT_EQ(UCONTEXT_GREGS_R12_OFFSET, offsetof(UContext<X86_64>, gregs.r12));
  EXPECT_EQ(UCONTEXT_GREGS_R13_OFFSET, offsetof(UContext<X86_64>, gregs.r13));
  EXPECT_EQ(UCONTEXT_GREGS_R14_OFFSET, offsetof(UContext<X86_64>, gregs.r14));
  EXPECT_EQ(UCONTEXT_GREGS_R15_OFFSET, offsetof(UContext<X86_64>, gregs.r15));
  EXPECT_EQ(UCONTEXT_GREGS_RDI_OFFSET, offsetof(UContext<X86_64>, gregs.rdi));
  EXPECT_EQ(UCONTEXT_GREGS_RSI_OFFSET, offsetof(UContext<X86_64>, gregs.rsi));
  EXPECT_EQ(UCONTEXT_GREGS_RBP_OFFSET, offsetof(UContext<X86_64>, gregs.rbp));
  EXPECT_EQ(UCONTEXT_GREGS_RBX_OFFSET, offsetof(UContext<X86_64>, gregs.rbx));
  EXPECT_EQ(UCONTEXT_GREGS_RDX_OFFSET, offsetof(UContext<X86_64>, gregs.rdx));
  EXPECT_EQ(UCONTEXT_GREGS_RAX_OFFSET, offsetof(UContext<X86_64>, gregs.rax));
  EXPECT_EQ(UCONTEXT_GREGS_RCX_OFFSET, offsetof(UContext<X86_64>, gregs.rcx));
  EXPECT_EQ(UCONTEXT_GREGS_RSP_OFFSET, offsetof(UContext<X86_64>, gregs.rsp));
  EXPECT_EQ(UCONTEXT_GREGS_RIP_OFFSET, offsetof(UContext<X86_64>, gregs.rip));
  EXPECT_EQ(UCONTEXT_GREGS_EFLAGS_OFFSET,
            offsetof(UContext<X86_64>, gregs.eflags));
  EXPECT_EQ(UCONTEXT_GREGS_CS_OFFSET, offsetof(UContext<X86_64>, gregs.cs));
  EXPECT_EQ(UCONTEXT_GREGS_GS_OFFSET, offsetof(UContext<X86_64>, gregs.gs));
  EXPECT_EQ(UCONTEXT_GREGS_FS_OFFSET, offsetof(UContext<X86_64>, gregs.fs));
  EXPECT_EQ(UCONTEXT_GREGS_SS_OFFSET, offsetof(UContext<X86_64>, gregs.ss));
  EXPECT_EQ(UCONTEXT_GREGS_DS_OFFSET, offsetof(UContext<X86_64>, gregs.ds));
  EXPECT_EQ(UCONTEXT_GREGS_ES_OFFSET, offsetof(UContext<X86_64>, gregs.es));
  EXPECT_EQ(UCONTEXT_GREGS_FS_BASE_OFFSET,
            offsetof(UContext<X86_64>, gregs.fs_base));
  EXPECT_EQ(UCONTEXT_GREGS_GS_BASE_OFFSET,
            offsetof(UContext<X86_64>, gregs.gs_base));
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

}  // namespace
}  // namespace silifuzz
