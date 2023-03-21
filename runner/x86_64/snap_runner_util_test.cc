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

#include "./runner/snap_runner_util.h"

#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>

#include "./snap/exit_sequence.h"
#include "./util/checks.h"
#include "./util/itoa.h"
#include "./util/nolibc_gunit.h"
#include "./util/ucontext/ucontext.h"

namespace silifuzz {
namespace {

TEST(SnapRunnerUtil, BasicTest) {
  InitSnapExit(&SnapExitImpl);

  // Assembly code between labels 1 and 2 is copied to code buffer for
  // execution.
  uint8_t* code_begin;
  uint8_t* code_end;
  asm volatile(
      " jmp 2f;"
      "1:;"
      " xorq $-1, %%rax;"
      " movq $42, %%rbx;"
      "2:;"
      " leaq 1b(%%rip), %0;"
      " leaq 2b(%%rip), %1;"
      : "=r"(code_begin), "=r"(code_end));

  const size_t kPageSize = getpagesize();

  void* code_page = mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  CHECK_NE(code_page, MAP_FAILED);

  size_t code_size = code_end - code_begin;
  memcpy(code_page, code_begin, code_size);
  size_t exit_sequence_size = WriteSnapExitSequence<X86_64>(
      reinterpret_cast<uint8_t*>(code_page) + code_size);
  CHECK_EQ(exit_sequence_size, GetSnapExitSequenceSize<X86_64>());
  mprotect(code_page, kPageSize, PROT_EXEC | PROT_READ);

  void* stack_page = mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE,
                          MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  CHECK_NE(stack_page, MAP_FAILED);

  // Initialize execution context using current register state.
  UContext execution_context;
  SaveUContextNoSyscalls(&execution_context);
  execution_context.gregs.rip = reinterpret_cast<uint64_t>(code_page);
  execution_context.gregs.rsp =
      reinterpret_cast<uint64_t>(stack_page) + kPageSize;
  execution_context.gregs.rdi = 0xabcd;
  EndSpot end_spot;
  RunSnap(execution_context, end_spot);

  // Verify that code has been executed.
  CHECK_EQ(snap_exit_context.gregs.rax, ~execution_context.gregs.rax);
  CHECK_EQ(snap_exit_context.gregs.rbx, 42);

  // Verify that RunnerReentry fixed up rdi, rsp & rip correctly.
  CHECK_EQ(snap_exit_context.gregs.rdi, execution_context.gregs.rdi);
  CHECK_EQ(snap_exit_context.gregs.rsp, execution_context.gregs.rsp);

  // A snapshot's ending rip is 1 after the ending instruction address.
  CHECK_EQ(snap_exit_context.gregs.rip,
           reinterpret_cast<uint64_t>(code_page) + code_size);

  // Check that the exit sequence wrote to the stack in the way we expected.
  uint8_t exit_sequence_stack_bytes[8];
  CHECK_EQ(ExitSequenceStackBytesSize<Host>(),
           sizeof(exit_sequence_stack_bytes));
  WriteExitSequenceStackBytes(snap_exit_context.gregs,
                              exit_sequence_stack_bytes);
  CHECK_EQ(
      memcmp(reinterpret_cast<const void*>(snap_exit_context.gregs.rsp -
                                           sizeof(exit_sequence_stack_bytes)),
             exit_sequence_stack_bytes, sizeof(exit_sequence_stack_bytes)),
      0);
}

}  // namespace
}  // namespace silifuzz

// ========================================================================= //

NOLIBC_TEST_MAIN({ RUN_TEST(SnapRunnerUtil, BasicTest); })
