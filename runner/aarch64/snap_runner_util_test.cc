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
#include <iterator>

#include "absl/base/macros.h"
#include "./runner/endspot.h"
#include "./runner/runner_main_options.h"
#include "./snap/exit_sequence.h"
#include "./util/aarch64/sve.h"
#include "./util/checks.h"
#include "./util/itoa.h"
#include "./util/nolibc_gunit.h"
#include "./util/reg_groups.h"
#include "./util/ucontext/ucontext.h"

namespace silifuzz {
namespace {

// Invert x0 and put 42 in x1
uint32_t kBasicSnap[] = {
    0xaa2003e0,  // mvn x0, x0
    0xd2800541,  // mov x1, #42
};

TEST(SnapRunnerUtil, BasicTest) {
  // Initialize register checksumming.
  InitRegisterGroupIO();
  snap_exit_register_group_io_buffer.register_groups =
      GetCurrentPlatformChecksumRegisterGroups();

  InitSnapExit(&SnapExitImpl);

  const size_t kPageSize = getpagesize();

  // Allocate code page.
  void* code_page = mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  CHECK_NE(code_page, MAP_FAILED);

  size_t code_size = sizeof(kBasicSnap);
  memcpy(code_page, kBasicSnap, code_size);
  size_t exit_sequence_size = WriteSnapExitSequence<AArch64>(
      reinterpret_cast<uint8_t*>(code_page) + code_size);
  CHECK_EQ(exit_sequence_size, GetSnapExitSequenceSize<AArch64>());
  // mprotect should sync the data cache and invalidate the instruction cache as
  // needed. No need to do it explicitly.
  CHECK_EQ(mprotect(code_page, kPageSize, PROT_EXEC | PROT_READ), 0);

  // Allocate stack page.
  // Note: in practice, this page may be immediately adjacent to the code page.
  void* stack_page = mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE,
                          MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  CHECK_NE(stack_page, MAP_FAILED);

  // Initialize execution context using current register state.
  // This way TLS stays valid during the test.
  UContext<Host> execution_context;
  UContextView<Host> execution_context_view(execution_context);

  SaveUContextNoSyscalls(&execution_context);

  // Initialize the general purpose registers with a pattern.
  for (int i = 0; i < std::size(execution_context.gregs.x); ++i) {
    execution_context.gregs.x[i] = 0xabcd + i;
  }

  // Initialize the floating point registers with a pattern. Note: These
  // registers are shared with the bottom 128-bits of the z registers.
  for (int i = 0; i < std::size(execution_context.fpregs.v); ++i) {
    execution_context.fpregs.v[i] = 0xface + i;
  }

  // Point to the allocated code and stack pages.
  execution_context.gregs.pc = reinterpret_cast<uint64_t>(code_page);
  execution_context.gregs.sp =
      reinterpret_cast<uint64_t>(stack_page) + kPageSize;

  // Execute.
  EndSpot end_spot;
  RunSnap(execution_context_view, RunnerMainOptions::Default(), end_spot);

  // Verify that test code has been executed.
  CHECK_EQ(snap_exit_context.gregs.x[0], ~execution_context.gregs.x[0]);
  CHECK_EQ(snap_exit_context.gregs.x[1], 42);

  // Registers that are not involved with the test code or the exit sequence.
  for (int i = 2; i < 30; ++i) {
    CHECK_EQ(snap_exit_context.gregs.x[i], execution_context.gregs.x[i]);
  }

  // In order to jump into the test code, one register needs to point to the
  // beginning of the code on entry. The register state will not match the
  // specified context. x30 was chosen for this role.
  CHECK_EQ(snap_exit_context.gregs.x[30], execution_context.gregs.pc);

  // Stack should not have been modified.
  CHECK_EQ(snap_exit_context.gregs.sp, execution_context.gregs.sp);

  // PC shoud point to end of the test code and before the exit sequence.
  CHECK_EQ(snap_exit_context.gregs.pc,
           reinterpret_cast<uint64_t>(code_page) + sizeof(kBasicSnap));

  // Other values that we let default to the current values, whatever they were.
  CHECK_EQ(snap_exit_context.gregs.pstate, execution_context.gregs.pstate);
  CHECK_EQ(snap_exit_context.gregs.tpidr, execution_context.gregs.tpidr);
  CHECK_EQ(snap_exit_context.gregs.tpidrro, execution_context.gregs.tpidrro);

  // FP state defaulted to the current values.
  for (int i = 0; i < std::size(execution_context.fpregs.v); ++i) {
    CHECK_EQ(snap_exit_context.fpregs.v[i], execution_context.fpregs.v[i]);
  }
  CHECK_EQ(snap_exit_context.fpregs.fpsr, execution_context.fpregs.fpsr);
  CHECK_EQ(snap_exit_context.fpregs.fpcr, execution_context.fpregs.fpcr);

  // Check that the exit sequence wrote to the stack in the way we expected.
  uint8_t exit_sequence_stack_bytes[16];
  CHECK_EQ(ExitSequenceStackBytesSize<Host>(),
           sizeof(exit_sequence_stack_bytes));
  WriteExitSequenceStackBytes(snap_exit_context.gregs,
                              exit_sequence_stack_bytes);
  CHECK_EQ(
      memcmp(reinterpret_cast<const void*>(snap_exit_context.gregs.sp -
                                           sizeof(exit_sequence_stack_bytes)),
             exit_sequence_stack_bytes, sizeof(exit_sequence_stack_bytes)),
      0);

  // Check register group IO buffer after snap exit.
  RegisterGroupIOBuffer<AArch64> expected_buffer{};
  if (SveIsSupported()) {
    expected_buffer.register_groups.SetSVE(true);
    size_t z_vl = SveGetCurrentVectorLength();

    // The bottom 128-bits of the z registers are shared with their
    // corresponding floating point registers, so we should expect the contents
    // to match the set pattern.
    for (int i = 0; i < std::size(execution_context.fpregs.v); ++i) {
      memcpy(&expected_buffer.z[i * z_vl], &execution_context.fpregs.v[i],
             sizeof(execution_context.fpregs.v[i]));
    }
  }

  CHECK_EQ(snap_exit_register_group_io_buffer.register_groups.Serialize(),
           expected_buffer.register_groups.Serialize());
  CHECK_EQ(memcmp(&snap_exit_register_group_io_buffer.ffr, &expected_buffer.ffr,
                  sizeof(expected_buffer.ffr)),
           0);
  CHECK_EQ(memcmp(&snap_exit_register_group_io_buffer.p, &expected_buffer.p,
                  sizeof(expected_buffer.p)),
           0);
  CHECK_EQ(memcmp(&snap_exit_register_group_io_buffer.z, &expected_buffer.z,
                  sizeof(expected_buffer.z)),
           0);
}

}  // namespace
}  // namespace silifuzz

// ========================================================================= //

NOLIBC_TEST_MAIN({ RUN_TEST(SnapRunnerUtil, BasicTest); })
