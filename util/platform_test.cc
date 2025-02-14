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

#include "./util/platform.h"

#include <string>

#include "gtest/gtest.h"
#include "absl/strings/ascii.h"
#include "absl/strings/match.h"
#include "absl/strings/str_replace.h"
#include "./proto/snapshot.pb.h"
#include "./util/arch.h"
#include "./util/itoa.h"

namespace silifuzz {

namespace {

// A quick test to catch when new platforms get added to prod.
// If this test becomes flaky then a new entry should be added to the PlatformId
// enum.
TEST(PlatformTest, CurrentPlatformId) {
  ASSERT_NE(CurrentPlatformId(), PlatformId::kUndefined)
      << "New platform was added to the fleet. Look at the error log and update"
      << " PlatformId enum accordingly";

  ASSERT_EQ(PlatformArchitecture(CurrentPlatformId()), Host::architecture_id);
}

TEST(PlatformTest, NoGaps) {
  ASSERT_STREQ(EnumStr(PlatformId::kNonExistent), "NON-EXISTENT-PLATFORM");
}

TEST(PlatformTest, PlatformArchitecture) {
  for (int i = proto::PlatformId_MIN; i < proto::PlatformId_MAX; ++i) {
    if (proto::PlatformId_IsValid(i)) {
      const std::string& enum_name = proto::PlatformId_Name(i);
      ArchitectureId arch = PlatformArchitecture(static_cast<PlatformId>(i));
      if (absl::StrContains(enum_name, "RESERVED") ||
          static_cast<PlatformId>(i) == PlatformId::kUndefined) {
        EXPECT_EQ(arch, ArchitectureId::kUndefined)
            << "Platform " << enum_name
            << " unexpectedly mapped to a defined architecture";
      } else {
        EXPECT_TRUE(arch == ArchitectureId::kX86_64 ||
                    arch == ArchitectureId::kAArch64)
            << "Platform " << enum_name
            << " doesn't map to a valid architecture";
      }
    }
  }
}

TEST(PlatformTest, PlatformNameMatchesEnum) {
  // `kAny` and `kNonExistent` are meta-values that won't be persisted in the
  // proto representation.
  EXPECT_EQ(proto::PlatformId_MAX, static_cast<int>(kMaxPlatformId) - 2)
      << "snapshot.proto is not up to date with the latest changes in platform "
         "ids.";
  for (int i = proto::PlatformId_MIN; i < proto::PlatformId_MAX; ++i) {
    if (proto::PlatformId_IsValid(i)) {
      std::string internal_name = absl::StrReplaceAll(
          absl::AsciiStrToUpper(EnumStr(static_cast<PlatformId>(i))),
          {{"-", "_"}});
      EXPECT_EQ(internal_name, proto::PlatformId_Name(i));
    }
  }
}

TEST(PlatformTest, EnumNameMap) {
  EXPECT_EQ(EnumNameMap<PlatformId>[static_cast<int>(kMaxPlatformId)],
            "NON-EXISTENT-PLATFORM")
      << "EnumNameMap is not up to date with the latest changes in platform "
         "ids.";
}

}  // namespace

}  // namespace silifuzz
