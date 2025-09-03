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

#include "./orchestrator/silifuzz_orchestrator.h"

#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace silifuzz {
namespace {
using testing::ElementsAre;
using testing::IsSupersetOf;

TEST(NextCorpusGenerator, Sequential) {
  NextCorpusGenerator gen(3, true, 0);
  std::vector<int> actual;
  for (int i = 0; i < 5; ++i) {
    actual.push_back(gen());
  }
  ASSERT_THAT(actual, ElementsAre(0, 1, 2, -1, -1));
}

TEST(NextCorpusGenerator, Random) {
  std::vector<std::string> src = {"1", "2", "3"};
  std::vector<std::string> result;
  NextCorpusGenerator gen(src.size(), false, 0);
  std::vector<std::string> actual;
  for (int i = 0; i < 100; ++i) {
    int idx = gen();
    ASSERT_GE(idx, 0);
    ASSERT_LT(idx, src.size());
    result.push_back(src[idx]);
  }
  ASSERT_THAT(result, IsSupersetOf(src))
      << "Expected a sequence of a 100 random elements to contain each element "
         "of the source at least once";
}

}  // namespace

}  // namespace silifuzz
