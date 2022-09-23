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

TEST(RawInsnsUtil, InstructionsToSnapshot) {
  absl::StatusOr<Snapshot> snapshot = InstructionsToSnapshot("\xCC", "my_id");
  ASSERT_THAT(snapshot, IsOk());
  EXPECT_EQ("my_id", snapshot->id());
  // data page + code page
  EXPECT_EQ(snapshot->num_pages(), 2);
  // must be executable
  EXPECT_THAT(snapshot->IsCompleteSomeState(), IsOk());
}

TEST(RawInsnsUtil, InstructionsToSnapshotRandomizedCodePage) {
  absl::StatusOr<Snapshot> snapshot =
      InstructionsToSnapshotRandomizedCodePage("\xCC", "my_id");
  ASSERT_THAT(snapshot, IsOk());
  EXPECT_EQ(0xac6'183c'3000, snapshot->ExtractRip(snapshot->registers()));
}

TEST(RawInsnsUtil, InstructionsToSnapshotId) {
  EXPECT_EQ(InstructionsToSnapshotId("Silifuzz"),
            "679016f223a6925ba69f055f513ea8aa0e0720ed");
}

}  // namespace
}  // namespace silifuzz
