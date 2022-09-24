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

#include "./tool_libs/simple_fix_tool_counters.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace silifuzz {
namespace fix_tool_internal {
namespace {

TEST(SimpleFixToolCounters, Value) {
  SimpleFixToolCounters counters;
  EXPECT_EQ(counters.GetValue("foo"), 0);
  counters.Increment("foo");
  EXPECT_EQ(counters.GetValue("foo"), 1);
  counters.IncrementBy("foo", 41);
  EXPECT_EQ(counters.GetValue("foo"), 42);
}

TEST(SimpleFixToolCounters, Merge) {
  SimpleFixToolCounters counters1;
  counters1.Increment("foo");
  counters1.Increment("bar");
  SimpleFixToolCounters counters2;
  counters2.Increment("bar");
  counters2.IncrementBy("buz", 3);

  counters1.Merge(counters2);
  EXPECT_EQ(counters1.GetValue("foo"), 1);
  EXPECT_EQ(counters1.GetValue("bar"), 2);
  EXPECT_EQ(counters1.GetValue("buz"), 3);
}

TEST(SimpleFixToolCounters, GetCounterNames) {
  SimpleFixToolCounters counters;
  counters.Increment("foo");
  counters.Increment("bar");
  counters.Increment("baz");
  EXPECT_THAT(counters.GetCounterNames(),
              ::testing::UnorderedElementsAre("foo", "bar", "baz"));
}

}  // namespace
}  // namespace fix_tool_internal
}  // namespace silifuzz
