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

#include "./snap/testing/snap_test_snapshots.h"

#include <sys/types.h>

#include <cstddef>
#include <cstring>

#include "./common/memory_perms.h"
#include "./common/snapshot.h"
#include "./common/snapshot_test_util.h"
#include "./common/snapshot_util.h"
#include "./snap/testing/snap_test_types.h"
#include "./util/checks.h"
#include "./util/misc_util.h"
#include "./util/ucontext/ucontext_types.h"

namespace silifuzz {
namespace {

Snapshot MakeBasicTestSnapshot() {
  Snapshot snapshot(Snapshot::CurrentArchitecture());
  snapshot.set_id("BasicTest");
  const size_t page_size = snapshot.page_size();
  Snapshot::Address code_page_address = 0x20000000ULL;
  Snapshot::Address data_page_address = code_page_address + page_size * 2;
  Snapshot::Address stack_page_address = data_page_address + page_size * 2;

  snapshot.add_memory_mapping(Snapshot::MemoryMapping::MakeSized(
      code_page_address, page_size, MemoryPerms::XR()));
  snapshot.add_memory_mapping(Snapshot::MemoryMapping::MakeSized(
      data_page_address, page_size, MemoryPerms::RW()));
  snapshot.add_memory_mapping(Snapshot::MemoryMapping::MakeSized(
      stack_page_address, page_size, MemoryPerms::RW()));

  // nop
  const Snapshot::ByteData kCodeBytes{0x90};
  snapshot.add_memory_bytes(
      Snapshot::MemoryBytes(code_page_address, kCodeBytes));

  GRegSet gregs;
  FPRegSet fpregs;
  memset(&gregs, 0, sizeof(gregs));
  gregs.rip = code_page_address;
  gregs.rsp = stack_page_address + page_size;
  gregs.rbx = data_page_address;
  memset(&fpregs, 0, sizeof(fpregs));

  fpregs.fcw = 0x37f;
  fpregs.mxcsr = 0x1f8;

  // Exercise x87 and SSE generation code path, using partially filled arrays.
  for (int i = 0; i < 4; ++i) {
    // Exponent 0x8000, significand 0x8000
    fpregs.st[i] = ((__uint128_t)0x8000ULL) << 64 | 0x8000ULL;
  }

  for (int i = 0; i < 6; ++i) {
    fpregs.xmm[i] = ((__uint128_t)0x2a) << 64 | ~0ULL;
  }

  snapshot.set_registers(ConvertRegsToSnapshot(gregs, fpregs));

  // The end state is bogus.  It does not match actual execution.
  Snapshot::Endpoint endpoint(code_page_address + kCodeBytes.size());
  gregs.rax = 0x42;
  Snapshot::EndState end_state(endpoint, ConvertRegsToSnapshot(gregs, fpregs));
  Snapshot::ByteData k42{42};
  end_state.add_memory_bytes(Snapshot::MemoryBytes(data_page_address, k42));
  end_state.add_platform(PlatformId::kIntelSkylake);
  snapshot.add_expected_end_state(end_state);
  return snapshot;
}

}  // namespace

Snapshot MakeSnapGeneratorTestSnapshot(SnapGeneratorTestType type) {
  switch (type) {
    case SnapGeneratorTestType::kBasicSnapGeneratorTest:
      return MakeBasicTestSnapshot();
    case SnapGeneratorTestType::kMemoryBytesPermsTest: {
      Snapshot snapshot = MakeBasicTestSnapshot();
      // This test uses the same snapshot as basic test but generates code
      // with non-default options.
      snapshot.set_id("MemoryBytesAttributesTest");
      return snapshot;
    }
    default:
      LOG_FATAL("Unexpected type ", ToInt(type));
  }
}

Snapshot MakeSnapRunnerTestSnapshot(SnapRunnerTestType type) {
  TestSnapshots::Options opts;
  // Need to force the normal (i.e. with registers) end state to confirm
  // to Snapify() contract.
  opts.force_normal_state = true;
  opts.read_address = 0x1000000;   // some mappable address
  opts.write_address = 0x1000000;  // some mappable address

  switch (type) {
    case SnapRunnerTestType::kEndsAsExpected:
      return TestSnapshots::Create(TestSnapshots::kEndsAsExpected);
    case SnapRunnerTestType::kRegsMismatch:
      return TestSnapshots::Create(TestSnapshots::kRegsMismatch);
    case SnapRunnerTestType::kMemoryMismatch:
      return TestSnapshots::Create(TestSnapshots::kMemoryMismatch);
    case SnapRunnerTestType::kRegsAndMemoryMismatch:
      return TestSnapshots::Create(TestSnapshots::kRegsAndMemoryMismatch);
    case SnapRunnerTestType::kRunaway:
      return TestSnapshots::Create(TestSnapshots::kRunaway, opts);
    case SnapRunnerTestType::kSyscall:
      return TestSnapshots::Create(TestSnapshots::kSyscall, opts);
    case SnapRunnerTestType::kSigSegvRead:
      return TestSnapshots::Create(TestSnapshots::kSigSegvRead, opts);
    case SnapRunnerTestType::kGeneralProtectionFault:
      return TestSnapshots::Create(TestSnapshots::kGeneralProtectionFault,
                                   opts);
    case SnapRunnerTestType::kSigIll:
      return TestSnapshots::Create(TestSnapshots::kSigIll, opts);
    case SnapRunnerTestType::kRegsMismatchRandom:
      return TestSnapshots::Create(TestSnapshots::kRegsMismatchRandom, opts);
    case SnapRunnerTestType::kINT3:
      return TestSnapshots::Create(TestSnapshots::kINT3, opts);
    case SnapRunnerTestType::kSplitLock:
      return TestSnapshots::Create(TestSnapshots::kSplitLock, opts);
  }
}

}  // namespace silifuzz
