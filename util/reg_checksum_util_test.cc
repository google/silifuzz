#include "./util/reg_checksum_util.h"

// Copyright 2023 The SiliFuzz Authors.
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

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "./util/arch.h"
#include "./util/reg_checksum.h"
#include "./util/testing/status_matchers.h"

using silifuzz::testing::IsOkAndHolds;
using silifuzz::testing::StatusIs;
using ::testing::HasSubstr;

namespace silifuzz {
namespace {

TEST(RegisterChecksumUtil, DeserializeEmptyData) {
  const std::string empty_data;
  auto checksum_or = DeserializeRegisterChecksum<X86_64>(empty_data);
  RegisterChecksum<X86_64> empty_checksum{};
  EXPECT_THAT(checksum_or, IsOkAndHolds(empty_checksum));
}

TEST(RegisterChecksumUtil, DeserializeValidChecksum) {
  RegisterChecksum<X86_64> original_checksum;
  original_checksum.register_groups.SetGPR(true);
  original_checksum.checksum = 1234;
  uint8_t buffer[256];
  ssize_t bytes_writtens =
      Serialize<X86_64>(original_checksum, buffer, sizeof(buffer));
  ASSERT_NE(bytes_writtens, -1);
  const std::string data(reinterpret_cast<const char*>(buffer), bytes_writtens);
  auto deserialized_checksum_or = DeserializeRegisterChecksum<X86_64>(data);
  EXPECT_THAT(deserialized_checksum_or, IsOkAndHolds(original_checksum));
}

TEST(RegisterChecksumUtil, DeserializeInvalidChecksum) {
  const std::string data("Bad data");
  auto deserialized_checksum_or = DeserializeRegisterChecksum<AArch64>(data);
  EXPECT_THAT(deserialized_checksum_or,
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("register checksum")));
}

}  // namespace
}  // namespace silifuzz
