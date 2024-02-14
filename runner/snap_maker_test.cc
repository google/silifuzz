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
#include "./util/testing/status_macros.h"
#include "./util/testing/status_matchers.h"

namespace silifuzz {
namespace {
using silifuzz::DefaultSnapMakerOptionsForTest;
using silifuzz::FixSnapshotInTest;
using silifuzz::testing::IsOk;
using silifuzz::testing::StatusIs;
using ::testing::AnyOf;
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
  // will fail due to snapshot overlapping with a reserved memory mapping.
  const auto vsyscallRegionAccessSnap =
      MakeSnapRunnerTestSnapshot<Host>(TestSnapshot::kVSyscallRegionAccess);
  SnapMaker::Options options = DefaultSnapMakerOptionsForTest();
  TraceOptions trace_options;
  trace_options.x86_filter_vsyscall_region_access = false;
  auto result_or =
      FixSnapshotInTest(vsyscallRegionAccessSnap, options, trace_options);
  EXPECT_THAT(
      result_or,
      AnyOf(IsOk(),
            StatusIs(absl::StatusCode::kInvalidArgument,
                     "memory mappings overlap reserved memory mappings")));

  trace_options.x86_filter_vsyscall_region_access = true;
  result_or =
      FixSnapshotInTest(vsyscallRegionAccessSnap, options, trace_options);

  // Depending on whether vsyscall is configured in the kernel, we will get
  // different results. If vsyscall is configured in the kernel vsyscall region
  // access is detected during tracing. On a machine running a kernel without
  // vsyscall configured, the vsyscall region is unmapped. When the test is
  // being made, the vsyscall page will be added to the data memory of the
  // snapshot. This will later cause the snapshot to be rejected due to snapshot
  // overlapping with a reserved mapping and it happens before snapshot tracing.
  EXPECT_THAT(
      result_or,
      AnyOf(StatusIs(absl::StatusCode::kInternal,
                     HasSubstr("May access vsyscall region")),
            StatusIs(absl::StatusCode::kInvalidArgument,
                     HasSubstr(
                         "memory mappings overlap reserved memory mappings"))));
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

}  // namespace
}  // namespace silifuzz
