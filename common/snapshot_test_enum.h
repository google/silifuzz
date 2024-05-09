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

#ifndef THIRD_PARTY_SILIFUZZ_COMMON_SNAPSHOT_TEST_ENUM_H_
#define THIRD_PARTY_SILIFUZZ_COMMON_SNAPSHOT_TEST_ENUM_H_

#include "./util/itoa.h"

namespace silifuzz {

enum class TestSnapshot {
  // Trivial snapshot with no code - ends in the expected endpoint.
  kEmpty = 0,

  // Snapshot ending in the expected endpoint.
  kEndsAsExpected,

  // Snapshot that does not end in any of its expected endpoints.
  kEndsUnexpectedly,

  // Snapshot ending with a register mismatch versus the expected end-state.
  kRegsMismatch,

  // Snapshot ending with a memory mismatch versus the expected end-state.
  kMemoryMismatch,

  // Snapshot ending with both register and memory mismatch versus
  // the expected end-state.
  kRegsAndMemoryMismatch,

  // Snapshot ending with a register mismatch versus the expected end-state.
  // The end register value(s) are highly random -- new on every run.
  kRegsMismatchRandom,

  // Snapshot ending with a memory mismatch versus the expected end-state.
  // The end memory value(s) are highly random -- new on every run.
  kMemoryMismatchRandom,

  // Snapshot ending with both register and memory mismatch versus
  // the expected end-state. The end register and memory value(s) are
  // highly random -- new on every run.
  kRegsAndMemoryMismatchRandom,

  // Snapshot with a single ICEBP instruction.
  // kICEBP, kBreakpoint, and kINT3_CD03 (as well as INT3 that models an
  // Endpoint::kInstruction) produce very similar behavior (SIGTRAP)
  // with slight variations that we want to regression-test for.
  kICEBP,

  // Snapshot with a single breakpoint instruction.
  kBreakpoint,

  // Snapshot with a single INT3 instruction encoded as 0xCD 0x03.
  kINT3_CD03,

  // Snapshot that causes SIGILL.
  kSigIll,

  // Snapshot that causes SIGSEGV on write.
  // All kSigSegv* snapshots fault on an address within the first 1K of
  // the address space (which is never mapped).
  kSigSegvWrite,
  kSigSegvWriteFixable,

  // Snapshot that causes SIGSEGV on read.
  kSigSegvRead,

  // Snapshot that causes SIGSEGV on read and can be fixed.
  kSigSegvReadFixable,

  // Snapshot that causes SIGSEGV on exec.
  kSigSegvExec,

  // Snapshot that makes a syscall. This particular snapshot makes a readonly
  // getcpu syscall and ignores the result i.e. it's deterministic.
  kSyscall,

  // Snapshot that causes a general protection fault.
  kGeneralProtectionFault,

  // Snapshot that changes ES, DS, FS and GS registers.
  kChangesSegmentReg,

  // Snapshot that contains a single IN instruction.
  kIn,

  // Snapshot that is a run-away (never reaches its end-point).
  kRunaway,

  // Snapshot that does lock access across cache lines on x86.
  kSplitLock,

  // Snapshot that sets three general purpose registers.
  kSetThreeRegisters,

  // Snapshot that calls _exit_group(0)
  kExitGroup,

  // Snapshot that accesses VSyscall memory region
  kVSyscallRegionAccess,

  // Contains a non-deterministic instruction (e.g. RDRAND) but the result
  // is not observable so this will replay deterministically.
  kHasUnobservableNondeterministicInsn,

  // Snapshot that exits with an unaligned stack pointer.
  kUalignedExitingStackPointer,

  // Snapshot that does not conform to fuzzing config.
  kFuzzingConfigNonconformance,

  // Snapshot that contains expensive instructions.
  kExpensiveInstructions,

  // Used to iterate over all possible TestSnapshots.
  kNumTestSnapshot
};

// EnumStr() works for TestSnapshot.
template <>
extern const char*
    EnumNameMap<TestSnapshot>[static_cast<int>(TestSnapshot::kNumTestSnapshot)];

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_COMMON_SNAPSHOT_TEST_ENUM_H_
