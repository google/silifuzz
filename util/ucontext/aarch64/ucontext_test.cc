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

#include <signal.h>
#include <sys/mman.h>

#include "gtest/gtest.h"
#include "./util/arch_mem.h"
#include "./util/checks.h"
#include "./util/ucontext/ucontext_types.h"

#ifdef UCONTEXT_NO_SYSCALLS
#define SAVE_UCONTEXT SaveUContextNoSyscalls
#define RESTORE_UCONTEXT RestoreUContextNoSyscalls
#else
#define SAVE_UCONTEXT SaveUContext
#define RESTORE_UCONTEXT RestoreUContext
#endif

extern "C" void NCZVSaveUContext(silifuzz::UContext<silifuzz::AArch64>* uc,
                                 uint32_t a, uint32_t b);
extern "C" uint64_t SaveUContextTwice(
    silifuzz::UContext<silifuzz::AArch64>* uc1,
    silifuzz::UContext<silifuzz::AArch64>* uc2);

namespace silifuzz {
namespace {

constexpr uint64_t N = 1ULL << 31;  // Negative
constexpr uint64_t Z = 1ULL << 30;  // Zero
constexpr uint64_t C = 1ULL << 29;  // Carry
constexpr uint64_t V = 1ULL << 28;  // Overflow
constexpr uint64_t NZCV_MASK = N | Z | C | V;
static_assert((NZCV_MASK & ~kPStateMask) == 0, "kPStateMask inconsistent");

constexpr uint64_t FPSR_DZC = (1ULL << 1);  // Divide by zero occured.
constexpr uint64_t FPSR_MASK = 0xf80000df;
static_assert((FPSR_DZC & ~FPSR_MASK) == 0, "FPSR_MASK inconsistent");

constexpr uint64_t FPCR_FZ = 1ULL << 24;  // Flush denormalized numbers to zero.
constexpr uint64_t FPCR_MASK = 0x07ff9f07;
static_assert((FPCR_FZ & ~FPCR_MASK) == 0, "FPCR_MASK inconsistent");

#if !defined(MEMORY_SANITIZER)
thread_local int dummy_tls;
#endif

// This pattern is designed to detect:
//   * reading the wrong register (every register has a different value)
//   * truncation (upper 32-bits are not zero)
//   * word swaps (upper and lower 32-bits are different)
uint64_t greg_pattern(int i) {
  uint64_t v = i;
  v |= (v ^ 0xff) << 8;
  v |= v << 48;
  return v;
}

// This pattern is designed to detect:
//   * reading the wrong register (every register has a different value)
//   * swizzles (every register has different bytes)
//   * truncation (upper bits are not zero)
// But it will not do a great job detecting word swaps inside a register. We use
// the "dup" instruction to init the register which writes a repeating pattern.
__uint128_t fpreg_pattern(int i) {
  __uint128_t v = i;
  v |= (v ^ 0xff) << 8;
  v |= v << 16;
  v |= v << 32;
  v |= v << 64;
  return v;
}

TEST(UContextTest, Accessors) {
  UContext<Host> uc;
  memset(&uc, 0xf0, sizeof(uc));

  constexpr uint64_t kInstructionPointer = 0x0123456789abcdef;
  constexpr uint64_t kStackPointer = 0xfedcba9876543210;
  uc.gregs.SetInstructionPointer(kInstructionPointer);
  uc.gregs.SetStackPointer(kStackPointer);

  EXPECT_EQ(uc.gregs.GetInstructionPointer(), kInstructionPointer);
  EXPECT_EQ(uc.gregs.pc, kInstructionPointer);

  EXPECT_EQ(uc.gregs.GetStackPointer(), kStackPointer);
  EXPECT_EQ(uc.gregs.sp, kStackPointer);
}

TEST(UContextTest, Consistency) {
  UContext<Host> uc1, uc2;

  // On calls between libraries, the dynamic linker can smash x9-x17 because
  // they are neither function arguments nor callee saved.
  // In practice, the dynamic linker smashes a larger set of registers the first
  // time a function is called, but only x16 and x17 on subsequent calls.
  // Call SaveUContext once to get lazy dynamic linking out of the way.
  SAVE_UCONTEXT(&uc1);

  // Clear memory differently to help notice uninitialzed bytes.
  memset(&uc1, 0x5a, sizeof(uc1));
  memset(&uc2, 0xa5, sizeof(uc2));

  uint64_t pre_frame = reinterpret_cast<uint64_t>(__builtin_frame_address(0));

  uint64_t callsite_offset = SaveUContextTwice(&uc1, &uc2);

  // Make sure we haven't corrupted the frame pointer.
  uint64_t post_frame = reinterpret_cast<uint64_t>(__builtin_frame_address(0));
  EXPECT_EQ(pre_frame, post_frame);

  // Shouldn't be needed except for unpoisoning memory for the sanitizer.
  ZeroOutRegsPadding(&uc1);
  ZeroOutRegsPadding(&uc2);

  // x0 should point to the context.
  EXPECT_EQ(uc1.gregs.x[0], reinterpret_cast<uint64_t>(&uc1));
  EXPECT_EQ(uc2.gregs.x[0], reinterpret_cast<uint64_t>(&uc2));

  // Validate constant-initialized registers.
  for (int i = 1; i < 29; i++) {
    // They should always be the same.
    EXPECT_EQ(uc1.gregs.x[i], uc2.gregs.x[i]) << "x" << i;
    // Jumping through a PLT can scramble x16 and x17.
    if (i == 16 || i == 17) continue;
    // Each register is initialzed to a unique pattern > 32 bits.
    EXPECT_EQ(uc1.gregs.x[i], greg_pattern(i)) << "x" << i;
  }

  // For stack and TLS pointers we're checking they're near a known stack or TLS
  // pointer. "Near" is tricky to define precisely since sanitizers and debug
  // mode may bloat memory layout. We chose an arbitrary but rather conservative
  // range of eight pages. It's better to be conservative rather than chase the
  // cases where the bound is too small.
  constexpr uint64_t pointer_slop = 8 * 4096;

  // Frame pointer.
  EXPECT_EQ(uc1.gregs.x[29], uc2.gregs.x[29]);
  // It's OK if the called function set up its own frame, or not.
  EXPECT_LE(uc1.gregs.x[29], pre_frame);
  EXPECT_GT(uc1.gregs.x[29], pre_frame - pointer_slop);

  // Link address.
  // The callsites should be a known number of bytes apart.
  EXPECT_EQ(uc1.gregs.x[30] + callsite_offset, uc2.gregs.x[30]);

  // Check that the stack pointer seems reasonable.
  EXPECT_EQ(uc1.gregs.sp, uc2.gregs.sp);
  // ASAN breaks this relationship.
#if !defined(ADDRESS_SANITIZER)
  uint64_t sp_estimate = reinterpret_cast<uint64_t>(&uc1);
  EXPECT_LT(uc1.gregs.sp, sp_estimate);
  EXPECT_GT(uc1.gregs.sp, sp_estimate - pointer_slop);
#endif

  // Program counter should be same as link register.
  EXPECT_EQ(uc1.gregs.x[30], uc1.gregs.pc);
  EXPECT_EQ(uc2.gregs.x[30], uc2.gregs.pc);

  // Make sure the accessor function works.
  EXPECT_EQ(uc1.gregs.GetInstructionPointer(), uc1.gregs.pc);
  EXPECT_EQ(uc2.gregs.GetInstructionPointer(), uc2.gregs.pc);

  // Check that pstate seems reasonable.
  EXPECT_EQ(uc1.gregs.pstate, uc2.gregs.pstate);
  EXPECT_EQ(uc1.gregs.pstate & ~kPStateMask, 0);

  // Check that the TLS register seems reasonable.
  EXPECT_EQ(uc1.gregs.tpidr, uc2.gregs.tpidr);
  // MSAN breaks this relationship.
#if !defined(MEMORY_SANITIZER)
  uint64_t tpidr_estimate = reinterpret_cast<uint64_t>(&dummy_tls);
  EXPECT_LT(uc1.gregs.tpidr, tpidr_estimate);
  EXPECT_GT(uc1.gregs.tpidr, tpidr_estimate - pointer_slop);
#endif

  // tpidrro is probally zero, but we don't have a guarantee.
  EXPECT_EQ(uc1.gregs.tpidrro, uc2.gregs.tpidrro);

  // The contexts should currently be different.
  EXPECT_NE(uc1.gregs, uc2.gregs);

  // Overwrite the values we know should be different.
  uc2.gregs.x[0] = uc1.gregs.x[0];
  uc2.gregs.x[30] = uc1.gregs.x[30];
  uc2.gregs.pc = uc1.gregs.pc;

  // Equality operator should work.
  EXPECT_EQ(uc1.gregs, uc2.gregs);

  // Floating point data registers should be the same.
  for (int i = 0; i < 32; i++) {
    EXPECT_EQ(uc1.fpregs.v[i], fpreg_pattern(i));
    EXPECT_EQ(uc1.fpregs.v[i], uc2.fpregs.v[i]);
  }

  // Floating point status register.
  EXPECT_EQ(uc1.fpregs.fpsr, uc2.fpregs.fpsr);
  EXPECT_EQ(uc1.fpregs.fpsr & ~FPSR_MASK, 0);
  // TODO: stonger test.

  // Floating point control register.
  EXPECT_EQ(uc1.fpregs.fpcr, uc2.fpregs.fpcr);
  EXPECT_EQ(uc1.fpregs.fpcr & ~FPCR_MASK, 0);
  // TODO: stonger test.

  // Equality operator should work.
  EXPECT_EQ(uc1.fpregs, uc2.fpregs);
}

TEST(UContextTest, FlagsZero) {
  UContext<Host> uc;
  NCZVSaveUContext(&uc, 0, 0);
  ZeroOutRegsPadding(&uc);
  EXPECT_EQ(uc.gregs.pstate & NZCV_MASK, Z);
}

TEST(UContextTest, FlagsOne) {
  UContext<Host> uc;
  NCZVSaveUContext(&uc, 1, 1);
  ZeroOutRegsPadding(&uc);
  EXPECT_EQ(uc.gregs.pstate & ~kPStateMask, 0);
  EXPECT_EQ(uc.gregs.pstate & NZCV_MASK, 0);
}

TEST(UContextTest, FlagsNegative) {
  UContext<Host> uc;
  NCZVSaveUContext(&uc, ~0, 0);
  ZeroOutRegsPadding(&uc);
  EXPECT_EQ(uc.gregs.pstate & ~kPStateMask, 0);
  EXPECT_EQ(uc.gregs.pstate & NZCV_MASK, N);
}

TEST(UContextTest, FlagsCancel) {
  UContext<Host> uc;
  NCZVSaveUContext(&uc, ~0, 1);
  ZeroOutRegsPadding(&uc);
  EXPECT_EQ(uc.gregs.pstate & ~kPStateMask, 0);
  EXPECT_EQ(uc.gregs.pstate & NZCV_MASK, Z | C);
}

TEST(UContextTest, SignOverflow) {
  UContext<Host> uc;
  NCZVSaveUContext(&uc, 0x7fffffff, 1);
  ZeroOutRegsPadding(&uc);
  EXPECT_EQ(uc.gregs.pstate & ~kPStateMask, 0);
  EXPECT_EQ(uc.gregs.pstate & NZCV_MASK, N | V);
}

TEST(UContextTest, Underflow) {
  UContext<Host> uc;
  NCZVSaveUContext(&uc, 0xc0000000, 0x80000000);
  ZeroOutRegsPadding(&uc);
  EXPECT_EQ(uc.gregs.pstate & ~kPStateMask, 0);
  EXPECT_EQ(uc.gregs.pstate & NZCV_MASK, C | V);
}

extern "C" void SaveThenRestore(UContext<AArch64>* save,
                                const UContextView<AArch64>& restore_view);

TEST(UContextTest, SetJmpLongJmp) {
  // Use SaveUContext/RestoreUContext similar to setjmp/longjmp.
  // This is the simplest smoke test we can do.
  UContext<Host> saved, restored;

  // Volatile to prevent it from being promoted to a register, which would turn
  // this code into an infinite loop.
  volatile unsigned int post_save_count = 0;
  SAVE_UCONTEXT(&saved);
  post_save_count++;
  ASSERT_LE(post_save_count, 2);
  if (post_save_count == 1) {
    // We just saved the current context.
    RESTORE_UCONTEXT(&saved);
    __builtin_unreachable();
  }
  // We have returned from the restore.
  ASSERT_EQ(post_save_count, 2);
  SAVE_UCONTEXT(&restored);

  // Make MSAN happy.
  ZeroOutRegsPadding(&saved);
  ZeroOutRegsPadding(&restored);

  // The save function should see the structure as its argument.
  EXPECT_EQ(saved.gregs.x[0], reinterpret_cast<uintptr_t>(&saved));
  EXPECT_EQ(restored.gregs.x[0], reinterpret_cast<uintptr_t>(&restored));

  // Different return points for the save functions.
  EXPECT_NE(saved.gregs.x[30], restored.gregs.x[30]);
  EXPECT_NE(saved.gregs.pc, restored.gregs.pc);

  // Same stack frame.
  EXPECT_EQ(saved.gregs.x[29], restored.gregs.x[29]);
  EXPECT_EQ(saved.gregs.sp, restored.gregs.sp);

  // Same thread-local storage.
  EXPECT_EQ(saved.gregs.tpidr, restored.gregs.tpidr);
  EXPECT_EQ(saved.gregs.tpidrro, restored.gregs.tpidrro);
}

// A helper class to allocate a page of memory with guard pages.
// Will automatically deallocate the memory on cleanup.
class TestStack {
 private:
  void* ptr;
  size_t sz;

 public:
  TestStack() : ptr(nullptr), sz(0) {
    constexpr size_t sz = 4096;
    void* ptr = mmap(nullptr, sz, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK_NE(ptr, MAP_FAILED);
    this->ptr = ptr;
    this->sz = sz;
  }
  ~TestStack() {
    if (ptr) {
      munmap(ptr, sz);
    }
  }

  // Return a pointer such that using more that `requested_size` bytes of stack
  // space should hit the guard page.
  uint64_t offset_ptr(size_t requested_size) {
    assert(requested_size <= sz);
    assert(requested_size % 16 == 0);
    return reinterpret_cast<uint64_t>(static_cast<uint8_t*>(ptr) +
                                      requested_size);
  }

  size_t size() const { return sz; }
};

class SignalBlocker {
 private:
  sigset_t saved;

 public:
  SignalBlocker() {
    sigset_t block;
    CHECK_EQ(sigfillset(&block), 0);
    std::cout << "Disabling signals for safety." << std::endl;
    CHECK_EQ(pthread_sigmask(SIG_SETMASK, &block, &saved), 0);
  }

  ~SignalBlocker() {
    CHECK_EQ(pthread_sigmask(SIG_SETMASK, &saved, nullptr), 0);
    std::cout << "Signals re-enabled." << std::endl;
  }
};

TEST(UContextTest, SaveThenRestore) {
  // An alternate stack to use inside the ASM code.
  TestStack stack;

  // `saved` is the context we save in the C code.
  // `expected` is the context we construct and jump to.
  // `actual` is the context we save inside the ASM code.
  // `reentry` is the state after returning to C code.
  UContext<Host> saved, expected, actual, reentry;
  UContextView<Host> saved_view(saved);

  // We run this test twice so we can validate the stack usage.
  for (int run_num = 0; run_num < 2; run_num++) {
    // Clear the contexts we're saving with different bit patterns to help
    // detect uninitialied memory.
    memset(&saved, 0x35, sizeof(saved));
    memset(&actual, 0xca, sizeof(actual));
    memset(&reentry, 0xac, sizeof(reentry));

    // Zero the context we're creating.
    memset(&expected, 0, sizeof(expected));

    // Save a copy of the current state so we can make sure our test values are
    // different.
    SAVE_UCONTEXT(&saved);

    // x0 points to the context we will be saving to.
    expected.gregs.x[0] = reinterpret_cast<uintptr_t>(&actual);
    // x1 points to the context view we will be restoring.
    expected.gregs.x[1] = reinterpret_cast<uintptr_t>(&saved_view);

    // Initialize gregs to a simple pattern.
    for (int i = 2; i < 30; i++) {
      expected.gregs.x[i] = i;
    }

    // Set the location we're jumping to.
    uintptr_t entry_point = reinterpret_cast<uintptr_t>(&SaveThenRestore);
    expected.gregs.x[30] = entry_point;
    expected.gregs.pc = entry_point;

    // Flip the NZCV bits.
    expected.gregs.pstate = saved.gregs.pstate ^ NZCV_MASK;

    expected.gregs.tpidr = 0x0123456789abcdef;
    // We can't actually set TPIDRRO_EL0 from a 64-bit process.
    expected.gregs.tpidrro = saved.gregs.tpidrro;

    // Run twice, the first time checking for using too much stack, the second
    // time checking for stack underflow.
    expected.gregs.sp = stack.offset_ptr(run_num ? stack.size() : 8 * 6);

    // A big prime number to help create a pseudo-random pattern in fpregs.
    constexpr __uint128_t P =
        (((__uint128_t)0x3a6037a8e2864274) << 64) | 0x28e629e23d8199b7;
    __uint128_t current = P;
    for (int i = 0; i < 32; i++) {
      current *= P;
      expected.fpregs.v[i] = current;
    }

    // Flip divide by zero status.
    expected.fpregs.fpsr = saved.fpregs.fpsr ^ FPSR_DZC;

    // Flip the flush to zero bit.
    expected.fpregs.fpcr = saved.fpregs.fpcr ^ FPCR_FZ;

    // This values need to be different for the test to be effective.
    EXPECT_NE(saved.gregs.pstate, expected.gregs.pstate);
    EXPECT_NE(saved.gregs.tpidr, expected.gregs.tpidr);
    EXPECT_NE(saved.fpregs.fpsr, expected.fpregs.fpsr);
    EXPECT_NE(saved.fpregs.fpcr, expected.fpregs.fpcr);

    // Note: if the dynamic linker tries to lazily resolve signals while we're
    // running with a minimal stack and bogus TLS, this test will crash.
    // This means we really need to have called all the functions the ASM code
    // will call from the C code, at least once. This should be the case since
    // we will have called save and restore before we ever enter the ASM code.
    {
      // Note: if a crash occurs inside the block, you will not see a stack
      // trace. We are tampering with the TLS and the signal handler that prints
      // the trace will hang in this state. We block signal handling to turn
      // this hang into a clean (but anonymous) crash.
      SignalBlocker blocker;

      volatile unsigned int post_save_count = 0;
      SAVE_UCONTEXT(&saved);
      // If you really need to a stack trace to debug, preserve TLS.
      // expected.gregs.tpidr = saved.gregs.tpidr;
      post_save_count++;
      ASSERT_LE(post_save_count, 2);
      if (post_save_count == 1) {
        // We just saved the current context.
        RESTORE_UCONTEXT(&expected);
        __builtin_unreachable();
      }
      // We have returned from the restore.
      ASSERT_EQ(post_save_count, 2);
    }

    // To the degree we can, check that the context was restored correctly.
    SAVE_UCONTEXT(&reentry);
    EXPECT_EQ(saved.gregs.x[29], reentry.gregs.x[29]);
    EXPECT_EQ(saved.gregs.sp, reentry.gregs.sp);
    EXPECT_EQ(saved.gregs.tpidr, reentry.gregs.tpidr);
    EXPECT_EQ(saved.gregs.tpidrro, reentry.gregs.tpidrro);
    EXPECT_EQ(saved.fpregs.fpcr, reentry.fpregs.fpcr);

    // Adjust the `actual` context in the ways we know it should deviate from
    // the `expected` context.

    // Jumping through the PLT may have clobbered these.
    actual.gregs.x[16] = expected.gregs.x[16];
    actual.gregs.x[17] = expected.gregs.x[17];

    // The save point is slightly after the restore point.
    constexpr uint64_t save_point_offset = 8;
    actual.gregs.x[30] -= save_point_offset;
    actual.gregs.pc -= save_point_offset;

    // A small stack frame is allocated to save the initial arguments.
    actual.gregs.sp += 16;

    // Check everything is the same.
    EXPECT_EQ(expected.gregs, actual.gregs);
    EXPECT_EQ(expected.fpregs, actual.fpregs);
  }
}

constexpr size_t kStackSize = 512;
// Reserve a little space after the stack pointer so we can detect bad writes.
constexpr size_t kStackOffset = kStackSize - 64;
constexpr uint8_t kStackPattern = 0xe1;

void PatternInitStack(uint8_t* stack) {
  memset(stack, kStackPattern, kStackSize);
}

void CheckEntryStackBytes(const GRegSet<AArch64>& gregs, const uint8_t* stack) {
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

void CheckExitStackBytes(const GRegSet<AArch64>& gregs, const uint8_t* stack) {
  constexpr size_t stack_bytes_used = 32;
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

extern "C" void CaptureStack(silifuzz::UContext<silifuzz::AArch64>* uc,
                             void* alternate_stack);

TEST(UContextTest, RestoreUContextStackBytes) {
  UContext<AArch64> test, saved;
  UContextView<AArch64> saved_view(saved);

  alignas(16) uint8_t entry_stack[kStackSize];
  PatternInitStack(entry_stack);

  alignas(16) uint8_t exit_stack[kStackSize];
  PatternInitStack(exit_stack);

  // Start with the existing context so we can keep TLS intact, etc.
  SAVE_UCONTEXT(&test);
  ZeroOutRegsPadding(&test);

  // Pattern init the GP registers.
  for (size_t i = 0; i < sizeof(test.gregs.x) / sizeof(test.gregs.x[0]); i++) {
    test.gregs.x[i] = (0xacbdefULL << 16) | i;
  }

  // Set up to restore the context into a call to CaptureStack
  test.gregs.pc = reinterpret_cast<uint64_t>(&CaptureStack);
  test.gregs.x[0] = reinterpret_cast<uint64_t>(&saved_view);
  test.gregs.x[1] = reinterpret_cast<uint64_t>(&exit_stack[kStackOffset]);
  test.gregs.sp = reinterpret_cast<uint64_t>(&entry_stack[kStackOffset]);

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

}  // namespace
}  // namespace silifuzz
