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

#include "./util/span_util.h"

#include <cmath>
#include <cstddef>
#include <type_traits>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/types/span.h"

using ::testing::SizeIs;

namespace silifuzz {
namespace {

// Verifies that `spans` covers `v` completely as PartitionEvenly() declares.
template <typename T>
void VerifySpan(const std::vector<absl::Span<T>>& spans,
                size_t expected_num_spans,
                const std::vector<typename std::remove_const<T>::type>& v) {
  ASSERT_THAT(spans, SizeIs(expected_num_spans));
  if (v.empty()) {
    ASSERT_TRUE(spans.empty());
    return;
  }

  const double average_size =
      static_cast<double>(v.size()) / expected_num_spans;
  const size_t upper_bound = static_cast<size_t>(ceil(average_size));
  const size_t lower_bound = static_cast<size_t>(floor(average_size));
  size_t offset = 0;
  for (size_t i = 0; i < spans.size(); offset += spans[i].size(), ++i) {
    EXPECT_GE(spans[i].size(), lower_bound);
    EXPECT_LE(spans[i].size(), upper_bound);
    EXPECT_EQ(spans[i].begin(), &v[offset]);
  }
  EXPECT_EQ(offset, v.size());
}

TEST(SpanUtil, SimpleTest) {
  struct Foo {
    Foo() = default;
    ~Foo() = default;

    // Not copyable to test handling of constness.
    Foo(const Foo&) = delete;
    Foo& operator=(const Foo&) = delete;
    Foo(Foo&&) = delete;
    Foo& operator=(Foo&&) = delete;

    int dummy = 0;
  };

  // kVectorSize % kNumSpans != 0 intentionally.
  constexpr size_t kVectorSize = 13;
  constexpr size_t kNumSpans = 5;

  std::vector<Foo> v1(kVectorSize);
  std::vector<absl::Span<Foo>> spans1 = PartitionEvenly(v1, kNumSpans);
  VerifySpan(spans1, kNumSpans, v1);

  const std::vector<Foo> v2(kVectorSize);
  std::vector<absl::Span<const Foo>> spans2 = PartitionEvenly(v2, kNumSpans);
  VerifySpan(spans2, kNumSpans, v2);
}

}  // namespace
}  // namespace silifuzz
