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
#include <type_traits>

#include "gtest/gtest.h"
#include "absl/strings/ascii.h"
#include "absl/strings/str_replace.h"
#include "google/protobuf/generated_enum_reflection.h"
#include "./proto/snapshot.pb.h"
#include "./util/arch.h"
#include "./util/itoa.h"

namespace silifuzz {

namespace {

using google::protobuf::GetEnumDescriptor;

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

TEST(PlatformTest, PlatformNameMatchesEnum) {
  static_assert(std::is_enum<proto::PlatformId>::value,
                "PlatformId is not an enum");
  for (int i = 0; i < sizeof(proto::PlatformId) * 8; ++i) {
    if (auto f = GetEnumDescriptor<proto::PlatformId>()->FindValueByNumber(i);
        f != nullptr) {
      std::string internal_name = absl::StrReplaceAll(
          absl::AsciiStrToUpper(EnumStr(static_cast<PlatformId>(i))),
          {{"-", "_"}});
      EXPECT_EQ(internal_name, f->name());
    }
  }
}

}  // namespace

}  // namespace silifuzz
