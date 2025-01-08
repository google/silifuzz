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

#include "./util/math.h"

#include "./util/checks.h"
#include "./util/nolibc_gunit.h"

namespace silifuzz {
namespace {

TEST(Math, RoundUpToPowerOfTwo) {
  int divisor = 1 << 8;
  for (int i = 0; i < divisor * 10; ++i) {
    int rounded = RoundUpToPowerOfTwo(i, divisor);
    CHECK_EQ(rounded % divisor, 0);
    if (i % divisor == 0) {
      CHECK_EQ(i, rounded);
    } else {
      CHECK_LT(i, rounded);
    }
  }
}

}  // namespace
}  // namespace silifuzz

NOLIBC_TEST_MAIN({ RUN_TEST(Math, RoundUpToPowerOfTwo); })
