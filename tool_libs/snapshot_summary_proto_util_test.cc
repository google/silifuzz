// Copyright 2026 The SiliFuzz Authors.
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

#include "./tool_libs/snapshot_summary_proto_util.h"

#include <cstdint>
#include <string>

#include "gtest/gtest.h"
#include "./common/memory_mapping.h"
#include "./common/memory_perms.h"
#include "./common/snapshot.h"
#include "./proto/snapshot.pb.h"
#include "./tool_libs/snap_group.h"
#include "./util/platform.h"
#include "./util/testing/status_macros.h"

namespace silifuzz {
namespace {

// Verifies that `ToProto()` and `FromProto()` round-trip a 64-bit sort key via
// `sort_key64` only. Builds a summary covering `PlatformId >= 32`, passes a
// proto pre-populated with a stale legacy `sort_key` to ensure `ToProto()`
// clears it, then serializes, parses, and decodes the proto back to C++.
TEST(SnapshotSummaryProto, RoundTrip64BitSortKey) {
  Snapshot snapshot(Snapshot::Architecture::kX86_64, "high_platform_snap");
  snapshot.add_memory_mapping(
      MemoryMapping::MakeSized(0x1234000ULL, 0x4000, MemoryPerms::XR()));
  Snapshot::EndState es(Snapshot::Endpoint(0x1234000ULL));
  es.add_platform(PlatformId::kIntelSapphireRapids);
  es.add_platform(PlatformId::kIntelGraniteRapids);
  es.add_platform(PlatformId::kIntelDiamondRapids);
  ASSERT_OK(snapshot.can_add_expected_end_state(es));
  snapshot.add_expected_end_state(es);

  const SnapshotGroup::SnapshotSummary original(snapshot);
  const int64_t expected_sort_key =
      -((int64_t{1} << static_cast<int>(PlatformId::kIntelSapphireRapids)) |
        (int64_t{1} << static_cast<int>(PlatformId::kIntelGraniteRapids)) |
        (int64_t{1} << static_cast<int>(PlatformId::kIntelDiamondRapids)));
  ASSERT_EQ(original.sort_key(), expected_sort_key);

  proto::SnapshotSummary summary_proto;
  // Verify reusing a proto with legacy `sort_key` leaves only `sort_key64`.
  summary_proto.set_sort_key(-12);
  SnapshotSummaryProto::ToProto(original, &summary_proto);
  EXPECT_FALSE(summary_proto.has_sort_key());
  ASSERT_TRUE(summary_proto.has_sort_key64());
  EXPECT_EQ(summary_proto.sort_key64(), expected_sort_key);

  std::string serialized;
  ASSERT_TRUE(summary_proto.SerializeToString(&serialized));
  proto::SnapshotSummary parsed_proto;
  ASSERT_TRUE(parsed_proto.ParseFromString(serialized));
  EXPECT_FALSE(parsed_proto.has_sort_key());
  EXPECT_TRUE(parsed_proto.has_sort_key64());

  ASSERT_OK_AND_ASSIGN(const SnapshotGroup::SnapshotSummary decoded,
                       SnapshotSummaryProto::FromProto(parsed_proto));
  EXPECT_EQ(decoded.id(), original.id());
  EXPECT_EQ(decoded.memory_mappings(), original.memory_mappings());
  EXPECT_EQ(decoded.sort_key(), expected_sort_key);
}

// Verifies backward compatibility with persisted protos that only set the
// legacy 32-bit `sort_key` field. Decodes a proto with `sort_key` populated and
// `sort_key64` unset, checking that `FromProto()` sign-extends it to `int64_t`.
TEST(SnapshotSummaryProto, LegacySortKeyFallback) {
  proto::SnapshotSummary legacy_proto;
  legacy_proto.set_id("legacy_snap");
  legacy_proto.set_sort_key(-12);

  ASSERT_OK_AND_ASSIGN(const SnapshotGroup::SnapshotSummary decoded,
                       SnapshotSummaryProto::FromProto(legacy_proto));
  EXPECT_EQ(decoded.id(), "legacy_snap");
  EXPECT_EQ(decoded.sort_key(), -12);
}

// Verifies that `FromProto()` prefers `sort_key64` over legacy `sort_key`
// whenever `sort_key64` is present. Decodes a proto with both fields set,
// testing both an explicit `0` (presence-based precedence) and a 64-bit key
// with `PlatformId >= 32`.
TEST(SnapshotSummaryProto, PrefersSortKey64OverLegacySortKey) {
  proto::SnapshotSummary mixed_proto;
  mixed_proto.set_id("mixed_snap");
  mixed_proto.set_sort_key(-12);
  // Zero `sort_key64` must still override legacy `sort_key` because field
  // presence determines precedence.
  mixed_proto.set_sort_key64(0);

  ASSERT_OK_AND_ASSIGN(const SnapshotGroup::SnapshotSummary decoded_zero,
                       SnapshotSummaryProto::FromProto(mixed_proto));
  EXPECT_EQ(decoded_zero.sort_key(), 0);

  const int64_t high_key =
      -(int64_t{1} << static_cast<int>(PlatformId::kIntelDiamondRapids));
  mixed_proto.set_sort_key64(high_key);
  ASSERT_OK_AND_ASSIGN(const SnapshotGroup::SnapshotSummary decoded_high,
                       SnapshotSummaryProto::FromProto(mixed_proto));
  EXPECT_EQ(decoded_high.sort_key(), high_key);
}

// Verifies the default sort key when neither `sort_key64` nor `sort_key` is
// populated. Calls `FromProto()` on a proto containing only `id` and asserts
// that the resulting `sort_key()` is `0`.
TEST(SnapshotSummaryProto, UnsetSortKeysDefaultToZero) {
  proto::SnapshotSummary empty_proto;
  empty_proto.set_id("empty_snap");

  ASSERT_OK_AND_ASSIGN(const SnapshotGroup::SnapshotSummary decoded,
                       SnapshotSummaryProto::FromProto(empty_proto));
  EXPECT_EQ(decoded.sort_key(), 0);
}

}  // namespace
}  // namespace silifuzz
