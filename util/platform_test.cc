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

#include "gtest/gtest.h"

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

}  // namespace

}  // namespace silifuzz
