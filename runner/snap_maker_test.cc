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

#include "./runner/snap_maker.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "./common/snapshot.h"
#include "./common/snapshot_test_enum.h"
#include "./player/trace_options.h"
#include "./runner/snap_maker_test_util.h"
#include "./snap/testing/snap_test_snapshots.h"
#include "./util/arch.h"
#include "./util/checks.h"
#include "./util/testing/status_macros.h"
#include "./util/testing/status_matchers.h"
#include "./util/testing/vsyscall.h"

namespace silifuzz {
namespace {
using silifuzz::DefaultSnapMakerOptionsForTest;
using silifuzz::FixSnapshotInTest;
using silifuzz::testing::IsOk;
using silifuzz::testing::StatusIs;
using ::testing::HasSubstr;
using ::testing::IsEmpty;

TEST(SnapMaker, AsExpected) {
  auto endsAsExpectedSnap =
      MakeSnapRunnerTestSnapshot<Host>(TestSnapshot::kEndsAsExpected);
  ASSERT_OK(FixSnapshotInTest(endsAsExpectedSnap));
}

TEST(SnapMaker, MemoryMismatchSnap) {
  auto memoryMismatchSnap =
      MakeSnapRunnerTestSnapshot<Host>(TestSnapshot::kMemoryMismatch);
  ASSERT_OK(FixSnapshotInTest(memoryMismatchSnap));
}

TEST(SnapMaker, RandomRegsMismatch) {
  auto regsMismatchRandomSnap =
      MakeSnapRunnerTestSnapshot<Host>(TestSnapshot::kRegsMismatchRandom);
  auto result_or = FixSnapshotInTest(regsMismatchRandomSnap);
  ASSERT_THAT(result_or, StatusIs(absl::StatusCode::kInternal,
                                  HasSubstr("non-deterministic")));
}

TEST(SnapMaker, SigSegvRead) {
  auto sigSegvReadSnap =
      MakeSnapRunnerTestSnapshot<Host>(TestSnapshot::kSigSegvReadFixable);
  ASSERT_OK_AND_ASSIGN(auto result, FixSnapshotInTest(sigSegvReadSnap));
  ASSERT_EQ(result.memory_mappings().size(),
            sigSegvReadSnap.memory_mappings().size() + 1)
      << "Expected Make to add 1 extra memory mapping";
  ASSERT_THAT(result.negative_memory_mappings(), IsEmpty());
}

TEST(SnapMaker, SigSegvExec) {
  const auto snapshot =
      MakeSnapRunnerTestSnapshot<Host>(TestSnapshot::kSigSegvExec);
  SnapMaker::Options options = DefaultSnapMakerOptionsForTest();
  TraceOptions trace_options;
  auto result_or = FixSnapshotInTest(snapshot, options, trace_options);
  EXPECT_THAT(result_or, StatusIs(absl::StatusCode::kInternal,
                                  HasSubstr("{SIG_SEGV/SEGV_CANT_EXEC}")));
}

TEST(SnapMaker, Idempotent) {
  auto memoryMismatchSnap =
      MakeSnapRunnerTestSnapshot<Host>(TestSnapshot::kMemoryMismatch);
  ASSERT_OK_AND_ASSIGN(auto result, FixSnapshotInTest(memoryMismatchSnap));
  ASSERT_OK_AND_ASSIGN(auto result2, FixSnapshotInTest(result));
  ASSERT_EQ(result2, result);
}

TEST(SnapMaker, SplitLock) {
#if !defined(__x86_64__)
  GTEST_SKIP() << "Splitlock detection implemented only on x86_64.";
#endif

  const auto splitLockSnap =
      MakeSnapRunnerTestSnapshot<Host>(TestSnapshot::kSplitLock);
  SnapMaker::Options options = DefaultSnapMakerOptionsForTest();
  TraceOptions trace_options;
  trace_options.x86_filter_split_lock = false;
  ASSERT_OK(FixSnapshotInTest(splitLockSnap, options, trace_options));

  trace_options.x86_filter_split_lock = true;
  auto result_or = FixSnapshotInTest(splitLockSnap, options, trace_options);
  EXPECT_THAT(result_or, StatusIs(absl::StatusCode::kInternal,
                                  HasSubstr("Split-lock insn")));
}

TEST(SnapMaker, ExitGroup) {
  auto exitGroupSnap =
      MakeSnapRunnerTestSnapshot<Host>(TestSnapshot::kExitGroup);
  absl::StatusOr<Snapshot> result = FixSnapshotInTest(exitGroupSnap);
  ASSERT_THAT(result.status(),
              StatusIs(absl::StatusCode::kInternal,
                       HasSubstr("Unlikely: snapshot kExitGroup had an "
                                 "undefined end state yet ran successfully")));
}

TEST(SnapMaker, VSyscallRegionAccess) {
#if !defined(__x86_64__)
  GTEST_SKIP()
      << "VSyscall region access detection implemented only on x86_64.";
#endif
  // Unfortunately this test depends on whether vsyscall is configured in
  // the Linux kernel. If it is configured, fixing will succeed.  Otherwise it
  // will fail when the runner tries to map a new page in the vsyscall region.
  const auto vsyscallRegionAccessSnap =
      MakeSnapRunnerTestSnapshot<Host>(TestSnapshot::kVSyscallRegionAccess);
  SnapMaker::Options options = DefaultSnapMakerOptionsForTest();
  TraceOptions trace_options;
  trace_options.x86_filter_vsyscall_region_access = false;
  auto result_or =
      FixSnapshotInTest(vsyscallRegionAccessSnap, options, trace_options);
  const std::string kSegvErrorMsg =
      "CannotAddMemory isn't Snap-compatible. Endpoint = "
      "{SIG_SEGV/SEGV_CANT_READ}";
  ASSERT_OK_AND_ASSIGN(const bool vsyscall_region_readable,
                       VSyscallRegionReadable());
  if (vsyscall_region_readable) {
    EXPECT_THAT(result_or, IsOk());
  } else {
    EXPECT_THAT(result_or,
                StatusIs(absl::StatusCode::kInternal, kSegvErrorMsg));
  }

  trace_options.x86_filter_vsyscall_region_access = true;
  result_or =
      FixSnapshotInTest(vsyscallRegionAccessSnap, options, trace_options);

  // If vsyscall is configured, we will get an error from the tracer, otherwise
  // we will get an error from the runner.
  if (vsyscall_region_readable) {
    EXPECT_THAT(result_or, StatusIs(absl::StatusCode::kInternal,
                                    HasSubstr("May access vsyscall region")));
  } else {
    EXPECT_THAT(result_or, StatusIs(absl::StatusCode::kInternal,
                                    HasSubstr(kSegvErrorMsg)));
  }
}

TEST(SnapMaker, MemoryAccess) {
#if !defined(__x86_64__)
  GTEST_SKIP() << "Memory access filter implemented only on x86_64.";
#endif

  const auto snapshot =
      MakeSnapRunnerTestSnapshot<Host>(TestSnapshot::kMemoryMismatch);
  SnapMaker::Options options = DefaultSnapMakerOptionsForTest();
  TraceOptions trace_options;
  trace_options.filter_memory_access = false;
  ASSERT_OK(FixSnapshotInTest(snapshot, options, trace_options));

  trace_options.filter_memory_access = true;
  auto result_or = FixSnapshotInTest(snapshot, options, trace_options);
  EXPECT_THAT(result_or, StatusIs(absl::StatusCode::kInternal,
                                  HasSubstr("Memory access not allowed")));
}

TEST(SnapMaker, CompatMode) {
  const auto snapshot =
      MakeSnapRunnerTestSnapshot<Host>(TestSnapshot::kSigSegvReadFixable);
  const auto snapshot2 = snapshot.Copy();

  SnapMaker::Options options = DefaultSnapMakerOptionsForTest();
  options.compatibility_mode = true;
  TraceOptions trace_options;
  ASSERT_OK_AND_ASSIGN(auto result,
                       FixSnapshotInTest(snapshot, options, trace_options));

  options.compatibility_mode = false;
  ASSERT_OK_AND_ASSIGN(auto result2,
                       FixSnapshotInTest(snapshot2, options, trace_options));
  EXPECT_EQ(result, result2);
  EXPECT_EQ(snapshot.memory_mappings(), snapshot2.memory_mappings());
}

TEST(SnapMaker, UnalignedExitStackPointer) {
#if !defined(__x86_64__)
  GTEST_SKIP()
      << "Unaligned exit stack pointer test implemented only on x86_64.";
#endif
  auto snapshot = MakeSnapRunnerTestSnapshot<Host>(
      TestSnapshot::kUalignedExitingStackPointer);
  SnapMaker::Options options = DefaultSnapMakerOptionsForTest();
  TraceOptions trace_options;
  EXPECT_OK(FixSnapshotInTest(snapshot, options, trace_options));
}

}  // namespace
}  // namespace silifuzz
