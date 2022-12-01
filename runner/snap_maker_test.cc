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
#include "./runner/snap_maker_test_util.h"
#include "./snap/testing/snap_test_snapshots.h"
#include "./util/testing/status_macros.h"
#include "./util/testing/status_matchers.h"

namespace silifuzz {
namespace {
using silifuzz::DefaultSnapMakerOptionsForTest;
using silifuzz::FixSnapshotInTest;
using silifuzz::testing::StatusIs;
using ::testing::HasSubstr;
using ::testing::IsEmpty;

TEST(SnapMaker, AsExpected) {
  auto endsAsExpectedSnap =
      MakeSnapRunnerTestSnapshot(TestSnapshot::kEndsAsExpected);
  ASSERT_OK(FixSnapshotInTest(endsAsExpectedSnap));
}

TEST(SnapMaker, MemoryMismatchSnap) {
  auto memoryMismatchSnap =
      MakeSnapRunnerTestSnapshot(TestSnapshot::kMemoryMismatch);
  ASSERT_OK(FixSnapshotInTest(memoryMismatchSnap));
}

TEST(SnapMaker, RandomRegsMismatch) {
  auto regsMismatchRandomSnap =
      MakeSnapRunnerTestSnapshot(TestSnapshot::kRegsMismatchRandom);
  auto result_or = FixSnapshotInTest(regsMismatchRandomSnap);
  ASSERT_THAT(result_or, StatusIs(absl::StatusCode::kInternal,
                                  HasSubstr("non-deterministic")));
}

TEST(SnapMaker, SigSegvRead) {
  auto sigSegvReadSnap = MakeSnapRunnerTestSnapshot(TestSnapshot::kSigSegvRead);
  ASSERT_OK_AND_ASSIGN(auto result, FixSnapshotInTest(sigSegvReadSnap));
  ASSERT_EQ(result.memory_mappings().size(),
            sigSegvReadSnap.memory_mappings().size() + 1)
      << "Expected Make to add 1 extra memory mapping";
  ASSERT_THAT(result.negative_memory_mappings(), IsEmpty());
}

TEST(SnapMaker, Idempotent) {
  auto memoryMismatchSnap =
      MakeSnapRunnerTestSnapshot(TestSnapshot::kMemoryMismatch);
  ASSERT_OK_AND_ASSIGN(auto result, FixSnapshotInTest(memoryMismatchSnap));
  ASSERT_OK_AND_ASSIGN(auto result2, FixSnapshotInTest(result));
  ASSERT_EQ(result2, result);
}

TEST(SnapMake, SplitLock) {
  const auto splitLockSnap =
      MakeSnapRunnerTestSnapshot(TestSnapshot::kSplitLock);
  SnapMaker::Options options = DefaultSnapMakerOptionsForTest();
  options.x86_filter_split_lock = false;
  ASSERT_OK(FixSnapshotInTest(splitLockSnap, options));

  options.x86_filter_split_lock = true;
  auto result_or = FixSnapshotInTest(splitLockSnap, options);
  EXPECT_THAT(result_or, StatusIs(absl::StatusCode::kInternal,
                                  HasSubstr("Split-lock insn")));
}

}  // namespace
}  // namespace silifuzz
