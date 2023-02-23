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

#include "./util/page_util.h"

#include <cstddef>

#include "./util/checks.h"
#include "./util/nolibc_gunit.h"

namespace silifuzz {
namespace {

TEST(PageUtil, IsPageAlignedInt) {
  CHECK(IsPageAligned((int)0));
  for (size_t i = 1; i < kPageSize; i++) {
    CHECK(!IsPageAligned(i));
  }
  CHECK(IsPageAligned(kPageSize));
}

TEST(PageUtil, IsPageAlignedPtr) {
  CHECK(IsPageAligned(reinterpret_cast<const uint8_t*>(0)));
  for (size_t i = 1; i < kPageSize; i++) {
    CHECK(!IsPageAligned(reinterpret_cast<const uint8_t*>(1)));
  }
  CHECK(IsPageAligned(reinterpret_cast<const uint8_t*>(kPageSize)));
}

TEST(PageUtil, RoundDownToPageAlignmentInt) {
  for (size_t i = 0; i < kPageSize * 10; i++) {
    size_t rounded = RoundDownToPageAlignment(i);
    CHECK(IsPageAligned(rounded));
    if (IsPageAligned(i)) {
      CHECK_EQ(i, rounded);
    } else {
      CHECK_GT(i, rounded);
    }
  }
}

TEST(PageUtil, RoundDownToPageAlignmentPtr) {
  for (size_t i = 0; i < kPageSize * 10; i++) {
    const uint8_t* ptr = reinterpret_cast<const uint8_t*>(i);
    const uint8_t* rounded = RoundDownToPageAlignment(ptr);
    CHECK(IsPageAligned(rounded));
    if (IsPageAligned(i)) {
      CHECK_EQ(ptr, rounded);
    } else {
      CHECK_GT(ptr, rounded);
    }
  }
}

TEST(PageUtil, RoundUpToPageAlignmentInt) {
  for (size_t i = 0; i < kPageSize * 10; i++) {
    size_t rounded = RoundUpToPageAlignment(i);
    CHECK(IsPageAligned(rounded));
    if (IsPageAligned(i)) {
      CHECK_EQ(i, rounded);
    } else {
      CHECK_LT(i, rounded);
    }
  }
}

TEST(PageUtil, RoundUpToPageAlignmentPtr) {
  for (size_t i = 0; i < kPageSize * 10; i++) {
    const uint8_t* ptr = reinterpret_cast<const uint8_t*>(i);
    const uint8_t* rounded = RoundUpToPageAlignment(ptr);
    CHECK(IsPageAligned(rounded));
    if (IsPageAligned(i)) {
      CHECK_EQ(ptr, rounded);
    } else {
      CHECK_LT(ptr, rounded);
    }
  }
}

}  // namespace
}  // namespace silifuzz

NOLIBC_TEST_MAIN({
  RUN_TEST(PageUtil, IsPageAlignedInt);
  RUN_TEST(PageUtil, IsPageAlignedPtr);
  RUN_TEST(PageUtil, RoundDownToPageAlignmentInt);
  RUN_TEST(PageUtil, RoundDownToPageAlignmentPtr);
  RUN_TEST(PageUtil, RoundUpToPageAlignmentInt);
  RUN_TEST(PageUtil, RoundUpToPageAlignmentPtr);
})
