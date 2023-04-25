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

#include <string>

#include "gtest/gtest.h"
#include "./common/raw_insns_util.h"
#include "./proto/snapshot.pb.h"
#include "./util/testing/status_macros.h"
#include "./util/testing/status_matchers.h"

namespace silifuzz {
namespace {

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

}  // namespace
}  // namespace silifuzz
