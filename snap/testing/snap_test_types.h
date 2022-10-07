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

#ifndef THIRD_PARTY_SILIFUZZ_SNAP_TESTING_SNAP_TEST_TYPES_H_
#define THIRD_PARTY_SILIFUZZ_SNAP_TESTING_SNAP_TEST_TYPES_H_

namespace silifuzz {

// For each type of generator and runner tests below, a Snapshot is defined.
// The snaphost is snapified using SnapGenerator::Snapified() and passed to
// SnapGenerator::DefineSnap() get a Snap corresponding to the Snapshot.

// Types of Snap generator tests. These tests are meant for testing code
// generation. The associated Snapshot and Snaps need not to be runnable.
enum class SnapGeneratorTestType {
  kBasicSnapGeneratorTest = 0,
  kFirstSnapGeneratorTest = kBasicSnapGeneratorTest,
  // Code for memory bytes permissions test is generated without forcing all
  // mapping writable. See snap_test_snaps_gen.cc.
  kMemoryBytesPermsTest = 1,
  // TODO(dougkwan): [as-needed] Add more test types when we expend the
  // capability of Snap or when we need regression tests.
  kLastSnapGeneratorTest = kMemoryBytesPermsTest,
};

// Types of Snap runner tests.
enum class SnapRunnerTestType {
  // We uses some snapshots from silifuzz::TestSnapshots that can be converted
  // to Snap. Note that we cannot reference enums in TestSnapshots here as due
  // to nolibc usage for this header.
  kEndsAsExpected = 0,  // See TestSnapshots::kEndsAsExpected,
  kFirstSnapRunnerTest = kEndsAsExpected,
  // See corresponding TestSnapshots::* snapshots
  kRegsMismatch,
  kMemoryMismatch,
  kRegsAndMemoryMismatch,
  kSigSegvRead,
  kRunaway,
  kGeneralProtectionFault,
  kSigIll,
  kRegsMismatchRandom,
  kINT3,
  kSyscall,
  kSplitLock,

  kLastSnapRunnerTest = kSplitLock,
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_SNAP_TESTING_SNAP_TEST_TYPES_H_
