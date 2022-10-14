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
  // code and RIP set to kFuzzCodePageAddr
  EXPECT_EQ(kFuzzCodePageAddr, snapshot->ExtractRip(snapshot->registers()));
}

TEST(RawInsnsUtil, InstructionsToSnapshotRandomizedCodePage) {
  absl::StatusOr<Snapshot> snapshot_1 =
      InstructionsToSnapshotRandomizedCodePage("\xCC", "my_id_1");
  ASSERT_THAT(snapshot_1, IsOk());
  constexpr uint64_t kSnapshot1CodePageAddr = 0xed0'6068'7000;
  EXPECT_EQ(kSnapshot1CodePageAddr,
            snapshot_1->ExtractRip(snapshot_1->registers()));

  absl::StatusOr<Snapshot> snapshot_2 =
      InstructionsToSnapshotRandomizedCodePage("\xAA", "my_id_2");
  ASSERT_THAT(snapshot_2, IsOk());
  constexpr uint64_t kSnapshot2CodePageAddr = 0x40'557c'4000;
  EXPECT_EQ(kSnapshot2CodePageAddr,
            snapshot_2->ExtractRip(snapshot_2->registers()));

  absl::StatusOr<Snapshot> snapshot_3 =
      InstructionsToSnapshotRandomizedCodePage("\xAA", "my_id_3");
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
