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

#include "./common/raw_insns_util.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "./proto/snapshot.pb.h"
#include "./util/testing/status_matchers.h"

namespace silifuzz {
namespace {

using silifuzz::testing::IsOk;

TEST(RawInsnsUtil, InstructionsToSnapshot_X86_64) {
  auto config = DEFAULT_X86_64_FUZZING_CONFIG;
  absl::StatusOr<Snapshot> snapshot =
      InstructionsToSnapshot_X86_64("\xCC", config);
  ASSERT_THAT(snapshot, IsOk());
  // data page + code page
  EXPECT_EQ(snapshot->num_pages(), 2);
  // must be executable
  EXPECT_THAT(snapshot->IsComplete(Snapshot::kUndefinedEndState), IsOk());

  uint64_t rip = snapshot->ExtractRip(snapshot->registers());
  EXPECT_GE(rip, config.code_range_start);
  EXPECT_LT(rip, config.code_range_limit);
}

TEST(RawInsnsUtil, InstructionsToSnapshot_X86_64_Stable) {
  absl::StatusOr<Snapshot> snapshot_2 = InstructionsToSnapshot_X86_64("\xAA");
  ASSERT_THAT(snapshot_2, IsOk());

  absl::StatusOr<Snapshot> snapshot_3 = InstructionsToSnapshot_X86_64("\xAA");
  ASSERT_THAT(snapshot_3, IsOk());
  EXPECT_EQ(snapshot_2->ExtractRip(snapshot_2->registers()),
            snapshot_3->ExtractRip(snapshot_3->registers()));
}

TEST(RawInsnsUtil, InstructionsToSnapshotId) {
  EXPECT_EQ(InstructionsToSnapshotId("Silifuzz"),
            "679016f223a6925ba69f055f513ea8aa0e0720ed");
}

}  // namespace
}  // namespace silifuzz
