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

#include "./util/strcat.h"

#include <string>

#include "gtest/gtest.h"
#include "./util/itoa.h"

namespace silifuzz {
namespace {

TEST(StrCat, All) {
  EXPECT_EQ(StrCat({}), std::string(""));
  EXPECT_EQ(StrCat({"st[", IntStr(0), "] = ", HexStr(16)}),
            std::string("st[0] = 0x10"));
  EXPECT_EQ(StrCat<0>({""}), std::string(""));
  EXPECT_DEATH_IF_SUPPORTED(StrCat<0>({"1"}), "MaxLength too small");
}

}  // namespace
}  // namespace silifuzz
