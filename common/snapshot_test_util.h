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

#ifndef THIRD_PARTY_SILIFUZZ_COMMON_SNAPSHOT_TEST_UTIL_H_
#define THIRD_PARTY_SILIFUZZ_COMMON_SNAPSHOT_TEST_UTIL_H_

#include <memory>
#include <string>
#include <vector>

#include "absl/time/time.h"
#include "./common/snapshot.h"
#include "./common/snapshot_types.h"
#include "./proto/snapshot.pb.h"

namespace silifuzz {

// Helpers for producing and testing the behavior of various representative
// test snapshots.
class TestSnapshots : private SnapshotTypeNames {
 public:
  // Reasonable value for PlayerOptions.run_time_budget for test snapshots.
  // Tests should use this bugdet if they want to reasonably cap their run time
  // which will otherwise suffer due to kRunaway snapshot.
  static constexpr inline absl::Duration kTestRunTimeBudget =
      absl::Milliseconds(100);

  // Types of test snapshot produced by TestSnapshots::Create().
  enum Type {
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
    // kICEBP, kINT3, and kINT3_CD03 (as well as INT3 that models an
    // Endpoint::kInstruction) produce very similar behavior (SIGTRAP)
    // with slight variations that we want to regression-test for.
    kICEBP,

    // Snapshot with a single INT3 instruction.
    kINT3,

    // Snapshot with a single INT3 instruction encoded as 0xCD 0x03.
    kINT3_CD03,

    // Snapshot that causes SIGILL.
    kSigIll,

    // Snapshot that causes SIGSEGV on write.
    // All kSigSegv* snapshots fault on an address within the first 1K of
    // the address space (which is never mapped).
    kSigSegvWrite,

    // Snapshot that causes SIGSEGV on read.
    kSigSegvRead,

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
  };

  // ----------------------------------------------------------------------- //

  // Options for Create() and CreateProto() below.
  class Options {
   public:
    static Options Default() { return Options(); }

    // If set, the returned snapshot will always have an undefined state.
    bool force_undefined_state = false;

    // If set, the returned snapshot will always have a normal state. This
    // is only useful for Snap/Runner testing.
    bool force_normal_state = false;

    // If set, the returned snapshot satisfies
    // Snapshot::MappedMemoryIsDefined().
    bool define_all_mapped = false;

    // Addresses from which to read/write/execute. The values can be accessed
    // by the snapshot as 0(%rbp), 8(%rbp) and 16(%rbp).
    // Used by some snapshots only.
    Snapshot::Address read_address = 0x300;
    Snapshot::Address write_address = 0x300;
    Snapshot::Address exec_address = 0x300;
  };

  // Creates a minimal snapshot for testing on the current architecture.
  static Snapshot Create(Type type, Options options = Options::Default());

  // Like Create() but returns the snapshot as a proto.
  static proto::Snapshot CreateProto(Type type,
                                     Options options = Options::Default());
};

// EnumStr() works for TestSnapshots::Type.
template <>
extern const char*
    EnumNameMap<TestSnapshots::Type>[ToInt(TestSnapshots::kSplitLock) + 1];

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_COMMON_SNAPSHOT_TEST_UTIL_H_
