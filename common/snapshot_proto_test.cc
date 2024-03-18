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

#include "./common/snapshot_proto.h"

#include <cstdint>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/statusor.h"
#include "./common/raw_insns_util.h"
#include "./common/snapshot.h"
#include "./common/snapshot_test_enum.h"
#include "./common/snapshot_test_util.h"
#include "./proto/snapshot.pb.h"
#include "./util/arch.h"
#include "./util/platform.h"
#include "./util/reg_checksum.h"
#include "./util/reg_group_set.h"
#include "./util/testing/status_macros.h"

namespace silifuzz {
namespace {
using ::testing::UnorderedElementsAreArray;

TEST(SnapshotProto, MetadataRoundtrip) {
  constexpr proto::SnapshotMetadata_Origin kOrigin =
      proto::SnapshotMetadata::UNICORN_FUZZING_ORIGIN;

  ASSERT_OK_AND_ASSIGN(Snapshot snapshot,
                       InstructionsToSnapshot<X86_64>("\xCC"));
  proto::Snapshot proto;
  SnapshotProto::ToProto(snapshot, &proto);
  proto.mutable_metadata()->set_origin(kOrigin);
  ASSERT_OK_AND_ASSIGN(snapshot, SnapshotProto::FromProto(proto));
  proto.Clear();
  SnapshotProto::ToProto(snapshot, &proto);
  ASSERT_EQ(proto.metadata().origin(), kOrigin);
}

TEST(SnapshotProto, MetadataStringRoundtrip) {
  constexpr proto::SnapshotMetadata_Origin kOrigin =
      proto::SnapshotMetadata::USE_STRING_ORIGIN;
  const std::string kCustomOrigin = "SOME_CUSTOM_ORIGIN";

  ASSERT_OK_AND_ASSIGN(Snapshot snapshot,
                       InstructionsToSnapshot<X86_64>("\xCC"));
  proto::Snapshot proto;
  SnapshotProto::ToProto(snapshot, &proto);
  proto.mutable_metadata()->set_origin(kOrigin);
  proto.mutable_metadata()->set_origin_string(kCustomOrigin);
  ASSERT_OK_AND_ASSIGN(snapshot, SnapshotProto::FromProto(proto));
  EXPECT_EQ(snapshot.metadata().origin_string(), kCustomOrigin);
  EXPECT_EQ(snapshot.metadata().origin(),
            Snapshot::Metadata::Origin::kUseString);
  proto.Clear();
  SnapshotProto::ToProto(snapshot, &proto);
  EXPECT_EQ(proto.metadata().origin(), kOrigin);
  EXPECT_EQ(proto.metadata().origin_string(), kCustomOrigin);
}

TEST(SnapshotProto, ArchRoundtrip) {
  // nop
  std::string instruction({0x1f, 0x20, 0x03, 0xd5});
  ASSERT_OK_AND_ASSIGN(Snapshot snapshot,
                       InstructionsToSnapshot<AArch64>(instruction));
  ASSERT_EQ(snapshot.architecture(), Snapshot::Architecture::kAArch64);

  proto::Snapshot proto;
  SnapshotProto::ToProto(snapshot, &proto);
  ASSERT_OK_AND_ASSIGN(snapshot, SnapshotProto::FromProto(proto));
  ASSERT_EQ(snapshot.architecture(), Snapshot::Architecture::kAArch64);
}

TEST(SnapshotProto, RegisterChecksumRoundtrip) {
  Snapshot::EndState endstate(Snapshot::Endpoint(0));
  RegisterChecksum<Host> register_checksum;
  register_checksum.register_groups =
      RegisterGroupSet<Host>::Deserialize(0x1234567);
  register_checksum.checksum = 0x89abcdef;
  uint8_t buffer[256];
  ssize_t len = Serialize(register_checksum, buffer, sizeof(buffer));
  ASSERT_NE(len, -1);
  Snapshot::ByteData serialized_checksum(reinterpret_cast<char*>(buffer), len);

  // Check conversion to proto.
  endstate.set_register_checksum(serialized_checksum);
  proto::EndState proto;
  SnapshotProto::ToProto(endstate, &proto);
  EXPECT_EQ(proto.register_checksum(), serialized_checksum);

  // Check conversion from proto.
  Snapshot::EndState endstate2(Snapshot::Endpoint(0));
  ASSERT_OK_AND_ASSIGN(endstate2, SnapshotProto::FromProto(proto));
  EXPECT_EQ(endstate2.register_checksum(), serialized_checksum);
}

TEST(SnapshotProto, TraceMetadataRoundtrip) {
  Snapshot snapshot = CreateTestSnapshot<Host>(TestSnapshot::kEndsAsExpected);
  Snapshot::TraceData t(1, "nop");
  t.add_platform(PlatformId::kIntelIcelake);
  t.add_platform(PlatformId::kIntelSkylake);
  snapshot.set_trace_data({t});
  proto::Snapshot proto;
  SnapshotProto::ToProto(snapshot, &proto);
  absl::StatusOr<Snapshot> got = SnapshotProto::FromProto(proto);
  ASSERT_OK(got);
  ASSERT_THAT(got->trace_data(),
              UnorderedElementsAreArray(snapshot.trace_data()));
}

}  // namespace
}  // namespace silifuzz
