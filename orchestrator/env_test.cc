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

#include "./orchestrator/env.h"

#include "gtest/gtest.h"

namespace silifuzz {
namespace {
TEST(Env, Hostname) {
  ASSERT_NE(Hostname(), "");
  ASSERT_TRUE(Hostname().data() == Hostname().data());
}

TEST(Env, ShortHostname) {
  auto short_hostname = ShortHostname();
  ASSERT_NE(short_hostname, "");
  ASSERT_EQ(short_hostname.find('.'), short_hostname.npos);
}
}  // namespace
}  // namespace silifuzz
