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

// This whole file is not compiled directly.
// Instead the REG_NAME string will be replaced by several register names
// and the results will be concatenated and then compiled
// -- see the BUILD rules.
//
// We could have done the same via a #define covering the
// TestOneRegister_REG_NAME() function, but it would be a very long define,
// thus hard to edit and with line numbers merged for all the code in it.

// This #if contains the top portion of the file that we want to be present
// only once when this file gets replicated multiple times into
// ucontext_test_lib_generated.cc by the genrule.
#ifndef THIRD_PARTY_SILIFUZZ_UTIL_UCONTEXT_UCONTEXT_TEST_LIB_CC_FILE_TOP_
#define THIRD_PARTY_SILIFUZZ_UTIL_UCONTEXT_UCONTEXT_TEST_LIB_CC_FILE_TOP_

#include <cstdint>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/attributes.h"
#include "./util/checks.h"
#include "./util/itoa.h"
#include "./util/logging_util.h"
#include "./util/misc_util.h"
#include "./util/ucontext/ucontext.h"
#include "./util/ucontext/ucontext_types.h"
#include "./util/ucontext/x86_64/x86_segment_base.h"

// Select version of UContext functions to test.
#ifdef UCONTEXT_NO_SYSCALLS
#define SAVE_UCONTEXT SaveUContextNoSyscalls
#define RESTORE_UCONTEXT RestoreUContextNoSyscalls
#else
#define SAVE_UCONTEXT SaveUContext
#define RESTORE_UCONTEXT RestoreUContext
#endif

namespace silifuzz {

bool HasSameSegmentRegisters(const GRegSet& actual, const GRegSet& expected) {
  return actual.cs == expected.cs && actual.gs == expected.gs &&
         actual.fs == expected.fs && actual.ss == expected.ss &&
         actual.ds == expected.ds && actual.es == expected.es;
}

bool HasCurrentSegmentRegisters(const UContext& ucontext) {
  UContext current;
  SAVE_UCONTEXT(&current);
  ZeroOutGRegsPadding(&current.gregs);  // to make MSAN happy about `cr`
  return HasSameSegmentRegisters(current.gregs, ucontext.gregs);
}

// See the comment in ucontext_test_lib.h.
int64_t test_reg_value;

// The following variables are all static instead of being local to
// TestOneRegister_REG_NAME() (which they conceptually are) so that
// compiler does not try to put them into registers and accessing them
// happens via just a const offset applied to rip and thus also
// needs no registers.
namespace {

// A value different from test_reg_value (we use ~test_reg_value).
int64_t different_test_reg_value;

// A spot to save/restore REG_NAME in case it's a callee-saved one.
int64_t saved_reg_value;

// The context we'll save/restore.
UContext ucontext;

// This lets us tell apart when we exit from SaveUContext()
// whether it's because we called just SaveUContext() or RestoreUContext()
// -- true and false value resp.
bool exercise_restore_ucontext;

// Used to test that we indeed executed the code after SaveUContext()
// twice - see exercise_restore_ucontext's comment.
int check_count;

// A tmp variable where we read REG_NAME into, so that we can then evaluate
// that value in C++ code.
int64_t reg_value;

// RestoreUContextNoSyscalls() loads fs and gs selectors but the only values
// allowed in user mode are null descriptors, which reset the segment register
// bases. Currently we can only set fs and gs bases with syscalls. So
// RestoreUContextNoSyscalls() cannot restore them and we need to save and
// restore them separately.
uint64_t fs_base;
uint64_t gs_base;

// Initialize the conceptually-local-to-TestOneRegister_REG_NAME() variables.
void InitLocals() {
  different_test_reg_value = ~test_reg_value;
#if !defined(MEMORY_SANITIZER)
  // Pattern-set to help catch uninitialized usage:
  memset(&ucontext, 0xAB, sizeof(ucontext));
#endif
  exercise_restore_ucontext = true;
  check_count = 0;
  fs_base = GetFSBase();
  gs_base = GetGSBase();
}

// For no syscall variant, we need to restore the fs and gs bases.
inline void RestoreFSGSBasesIfNecessary() {
#if defined(UCONTEXT_NO_SYSCALLS)
  SetFSBase(fs_base);
  SetGSBase(gs_base);
#endif
}

}  // namespace

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_UCONTEXT_UCONTEXT_TEST_LIB_CC_FILE_TOP_

// ========================================================================= //

namespace silifuzz {

// See the comment in ucontext_test_lib.h.
//
// It's important for this function to be
// - Not inlined.
// - Not optimized (done with copts in the BUILD rile).
//   Optimization is too aggressive: after doing one register->variable read
//      asm("movq %0, %%REG_NAME" : : "r"(foo_var));
//   another such read from the same REG_NAME is replaced by the compiler
//   by reading from foo_var even though there's an asm instruction to write
//   into REG_NAME between the above two reads. Excessive use of volatile
//   on asm() and variables does not seem to help this.
ABSL_ATTRIBUTE_NOINLINE void TestOneRegister_REG_NAME() {
  // Prevent the REG_NAME register from being used for local variables.
  register int64_t reserved_REG_NAME asm("REG_NAME") __attribute__((unused));

  // Save the REG_NAME register.
  asm("movq %%REG_NAME, %0" : "=r"(saved_reg_value) :);

  LOG_INFO("TestOneRegister_REG_NAME():");

  InitLocals();

  // Set the register to test_reg_value.
  asm("movq %0, %%REG_NAME" : : "r"(test_reg_value));

  // Save the context.
  SAVE_UCONTEXT(&ucontext);
  // RestoreUContext() below will bring control right here.

  // Read the REG_NAME register to reg_value.
  asm("movq %%REG_NAME, %0" : "=r"(reg_value) :);

  // If the register was rpb, we have to restore it before we do other things.
  if (&ucontext.gregs.REG_NAME == &ucontext.gregs.rbp) {
    asm("movq %0, %%REG_NAME" : : "r"(saved_reg_value));
  }

  // For non-syscalls version, we need to restore FS and GS base ourself.
  RestoreFSGSBasesIfNecessary();
  ZeroOutRegsPadding(&ucontext);

  // Check that both the actual register value and its value in the saved
  // context are as expected:
  if (&ucontext.gregs.REG_NAME == &ucontext.gregs.rdi) {
    // Special case for rdi: it always point to the arg of SaveUContext():
    CHECK_EQ(reg_value, AsInt(&ucontext));
    CHECK_EQ(ucontext.gregs.REG_NAME, AsInt(&ucontext));
  } else {
    CHECK_EQ(reg_value, test_reg_value);
    CHECK_EQ(ucontext.gregs.REG_NAME, test_reg_value);
  }

  check_count += 1;  // Count after-SaveUContext() control flows passages.

  if (exercise_restore_ucontext) {
    exercise_restore_ucontext = false;
    LOG_INFO("  Doing RestoreUContext()");

    // Set a different register value.
    asm("movq %0, %%REG_NAME" : : "r"(different_test_reg_value));

    // Read the register to reg_value and verify it's indeed different.
    asm("movq %%REG_NAME, %0" : "=r"(reg_value) :);
    // Have to restore rbp before we do other things:
    if (&ucontext.gregs.REG_NAME == &ucontext.gregs.rbp) {
      asm("movq %0, %%REG_NAME" : : "r"(saved_reg_value));
    }
    CHECK_EQ(reg_value, different_test_reg_value);
    CHECK_NE(reg_value, test_reg_value);

    CHECK(HasCurrentSegmentRegisters(ucontext));

    // Set different_test_reg_value again right before calling RestoreUContext()
    // in case it was clobbered above.
    asm("movq %0, %%REG_NAME" : : "r"(different_test_reg_value));

    // Load `ucontext` thus jumping control back right after
    // SaveUContext() above.
    RESTORE_UCONTEXT(&ucontext);

    LOG_FATAL("Unreachable");
  }

  // Verify that we did RestoreUContext() and thus did the register value
  // testing for the state resulting from it.
  CHECK_EQ(check_count, 2);

  // Restore the REG_NAME register.
  asm("movq %0, %%REG_NAME" : : "r"(saved_reg_value));
}

// ========================================================================= //

// The code protected by this #if defines couple of funcitons not parameterized
// by REG_NAME, so it should not be replicated when this file gets replicated
// multiple times into ucontext_test_lib_generated.cc by the genrule.

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_UCONTEXT_UCONTEXT_TEST_LIB_CC_ONCE_
#define THIRD_PARTY_SILIFUZZ_UTIL_UCONTEXT_UCONTEXT_TEST_LIB_CC_ONCE_

// This helper exists (vs inlining the code into the point of usage below)
// just to force a change to rsp.
ABSL_ATTRIBUTE_NOINLINE static void TestSpecialRegisters_rsp_rip_Helper() {
  // Verify that rip and rsp are indeed different.
  reg_value = CurrentInstructionPointer();
  CHECK_NE(ucontext.gregs.rip, reg_value);
  asm("movq %%rsp, %0" : "=r"(reg_value) :);
  CHECK_NE(ucontext.gregs.rsp, reg_value);

  CHECK(HasCurrentSegmentRegisters(ucontext));

  // Load `ucontext` thus jumping control back right after
  // SaveUContext() in TestSpecialRegisters_rsp_rip().
  RESTORE_UCONTEXT(&ucontext);
}

// See comment in ucontext_test_lib.h.
void TestSpecialRegisters_rsp_rip() {
  LOG_INFO("TestSpecialRegisters_rsp_rip():");

  InitLocals();

  // Save rip register to saved_reg_value.
  saved_reg_value = CurrentInstructionPointer();

  // Save the context.
  SAVE_UCONTEXT(&ucontext);
  // RestoreUContext() in TestSpecialRegisters_rsp_rip_Helper() will bring
  // control right here.

  // Read rip register to reg_value.
  reg_value = CurrentInstructionPointer();

  // For non-syscalls version, we need to restore FS and GS base ourself.
  RestoreFSGSBasesIfNecessary();
  ZeroOutRegsPadding(&ucontext);

  // The rip checks below also test CurrentInstructionPointer().

  // rip is not far after the one taken before the SaveUContext() call:
  CHECK_GT(ucontext.gregs.rip, saved_reg_value);
  // Sanitizers inject some code; we do not bother adjusting the rip range to
  // cover that case.
#if !defined(MEMORY_SANITIZER) && !defined(THREAD_SANITIZER)
  CHECK_LT(ucontext.gregs.rip, saved_reg_value + 20);
#endif

  // rip is not far before the one taken after the SaveUContext() call:
  CHECK_LT(ucontext.gregs.rip, reg_value);
#if !defined(MEMORY_SANITIZER)
  CHECK_GT(ucontext.gregs.rip, reg_value - 10);
#endif

  // Sanity checks: rip-s taken around SaveUContext() call are ordered and
  // are within this function:
  CHECK_LT(saved_reg_value, reg_value);
  CHECK_GT(saved_reg_value,
           reinterpret_cast<uint64_t>(&TestSpecialRegisters_rsp_rip));
#if !defined(MEMORY_SANITIZER) && !defined(ADDRESS_SANITIZER)
  CHECK_LT(reg_value,
           reinterpret_cast<uint64_t>(&TestSpecialRegisters_rsp_rip) + 500);
#endif

  // Read rsp register to reg_value and check that its value in the saved
  // context is as expected:
  asm("movq %%rsp, %0" : "=r"(reg_value) :);
  CHECK_EQ(ucontext.gregs.rsp, reg_value);

  check_count += 1;  // Count after-SaveUContext() control flows passages.

  if (exercise_restore_ucontext) {
    exercise_restore_ucontext = false;
    LOG_INFO("  Doing RestoreUContext()");

    // rip is already different, to change rsp we make a function call:
    TestSpecialRegisters_rsp_rip_Helper();

    LOG_FATAL("Unreachable");
  }

  // Verify that we did RestoreUContext() and thus did the register value
  // testing for the state resulting from it.
  CHECK_EQ(check_count, 2);
}

// ========================================================================= //

// The context that TestUContextVarious() will save via lib'c getcontext().
static ucontext_t libc_ucontext;

// Like test_reg_value for eflags values for TestUContextVarious(), except that
// we just save the eflags value before SaveUContext() into this (whereas the
// value for test_reg_value is freely chosen).
static int64_t flags_value;

// See comment in ucontext_test_lib.h.
void TestUContextVarious() {
  // Save eflags value to saved_reg_value.
  asm("pushfq\n"
      "popq %0"
      : "=r"(saved_reg_value)
      :);

  LOG_INFO("TestUContextVarious():");

  InitLocals();
#if !defined(MEMORY_SANITIZER)
  // Pattern-set to help catch uninitialized usage:
  memset(&libc_ucontext, 0xCD, sizeof(libc_ucontext));
#endif

  // The direction bit in eflags.
  static constexpr int64_t kDirectionFlagBit = 0x400;

  getcontext(&libc_ucontext);

  // Set the direction flag bit in eflags.
  asm("std");
  // Read the eflags value to flags_value.
  asm("pushfq\n"
      "popq %0"
      : "=r"(flags_value)
      :);

  // Save the context.
  SAVE_UCONTEXT(&ucontext);
  // RestoreUContext() below will bring control right here.

  // Read the eflags value to reg_value.
  asm("pushfq\n"
      "popq %0"
      : "=r"(reg_value)
      :);

  // Restore the eflags value quickly.
  // Keeping the direction flag set badly impacts e.g. crash logging.
  asm("pushq %0\n"
      "popfq"
      :
      : "r"(saved_reg_value));

  // For non-syscalls version, we need to restore FS and GS base ourself.
  RestoreFSGSBasesIfNecessary();
  ZeroOutRegsPadding(&ucontext);

  // Check that both the actual eflags value and its value in the saved
  // context are as expected:
#if !defined(MEMORY_SANITIZER)  // MSAN-injected code changes eflags a bit
  CHECK_EQ(reg_value, flags_value);
  CHECK_EQ(ucontext.gregs.eflags, flags_value);
#endif
  // Check that the direction flag bit is indeed set:
  CHECK_EQ(ucontext.gregs.eflags & kDirectionFlagBit, kDirectionFlagBit);

  // Read segment register values into reg_value and check that thier values
  // in the saved context are as expected:
  asm volatile("movq %%cs, %0" : "=r"(reg_value) :);
  EXPECT_EQ(ucontext.gregs.cs, reg_value);
  asm volatile("movq %%gs, %0" : "=r"(reg_value) :);
  EXPECT_EQ(ucontext.gregs.gs, reg_value);
  asm volatile("movq %%fs, %0" : "=r"(reg_value) :);
  EXPECT_EQ(ucontext.gregs.fs, reg_value);
  asm volatile("movq %%ss, %0" : "=r"(reg_value) :);
  EXPECT_EQ(ucontext.gregs.ss, reg_value);
  asm volatile("movq %%ds, %0" : "=r"(reg_value) :);
  EXPECT_EQ(ucontext.gregs.ds, reg_value);
  asm volatile("movq %%es, %0" : "=r"(reg_value) :);
  EXPECT_EQ(ucontext.gregs.es, reg_value);

  // Verify that fpregs pointer is set correctly.
  CHECK_EQ(libc_ucontext.uc_mcontext.fpregs, &libc_ucontext.__fpregs_mem);

  // Verify fpregs values against libc's getcontext()
  // -- the latter only saves these:
  if (DEBUG_MODE) {
    LOG_INFO("libc_ucontext FP registers vs ucontext:");
    // Layout should be the same since they are both based on fxstore64.
    LogFPRegs(*reinterpret_cast<FPRegSet*>(libc_ucontext.uc_mcontext.fpregs),
              false, &ucontext.fpregs, true);
  }
  EXPECT_EQ(ucontext.fpregs.fcw, libc_ucontext.uc_mcontext.fpregs->cwd);
  if (0) {
    // These are saved by both getcontext() and SaveUContext(),
    // but for some reason fxsave and fnstenv instructions result in
    // different values being saved.
    // fxrstor also barfs if we were to apply fnstenv over the result of fxsave.
    // If necessary we could allocate a separate space in UContext to
    // also save/restore with fnstenv and fldenv.
    EXPECT_EQ(ucontext.fpregs.fsw, libc_ucontext.uc_mcontext.fpregs->swd);
    EXPECT_EQ(ucontext.fpregs.ftw, libc_ucontext.uc_mcontext.fpregs->ftw);
    EXPECT_EQ(ucontext.fpregs.fop, libc_ucontext.uc_mcontext.fpregs->fop);
    EXPECT_EQ(ucontext.fpregs.rip, libc_ucontext.uc_mcontext.fpregs->rip);
    EXPECT_EQ(ucontext.fpregs.rdp, libc_ucontext.uc_mcontext.fpregs->rdp);
  }
  EXPECT_EQ(ucontext.fpregs.mxcsr, libc_ucontext.uc_mcontext.fpregs->mxcsr);

  check_count += 1;  // Count after-SaveUContext() control flows passages.

  if (exercise_restore_ucontext) {
    exercise_restore_ucontext = false;
    LOG_INFO("  Doing RestoreUContext()");

    // Clear the direction flag bit in eflags
    // to test restoration in RestoreUContext().
    asm volatile("cld");

    // Read the eflags value to reg_value.
    asm volatile(
        "pushfq\n"
        "popq %0"
        : "=r"(reg_value)
        :);
    // Check that the direction flag bit is indeed cleared:
    CHECK_EQ(reg_value & kDirectionFlagBit, 0);
    CHECK_NE(reg_value, flags_value);

    // TODO(ksteuck): [test] Modify some fp regs here to test restoration
    // in RestoreUContext(): Maybe do some fp math and verify that
    // SaveUContext() results in a different state.

    CHECK(HasCurrentSegmentRegisters(ucontext));

    // Clear the direction flag bit in eflags again right before calling
    // RestoreUContext() in case it was clobbered above.
    asm volatile("cld");

    // Load `ucontext` thus jumping control back right after
    // SaveUContext() above.
    RESTORE_UCONTEXT(&ucontext);
    LOG_FATAL("Unreachable");
  }

  // Verify that we did RestoreUContext() and thus did the register value
  // testing for the state resulting from it.
  CHECK_EQ(check_count, 2);

  // Restore the eflags value.
  asm volatile(
      "pushq %0\n"
      "popfq"
      :
      : "r"(saved_reg_value));
}

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_UCONTEXT_UCONTEXT_TEST_LIB_CC_ONCE_

}  // namespace silifuzz

// ========================================================================= //
