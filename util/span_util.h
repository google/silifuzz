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
//
// Utility functions for absl::Span
#ifndef THIRD_PARTY_SILIFUZZ_UTIL_SPAN_UTIL_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_SPAN_UTIL_H_

#include <stddef.h>

#include <string>
#include <type_traits>
#include <vector>

#include "absl/types/span.h"
#include "./util/checks.h"

namespace silifuzz {

// Partitions a vector-like container `v` into roughly `n` equal sized parts. It
// returns a vector<Span<...>> such that:
// 1. each span has size between floor(v.size()/n) and ceil(v.size())
// 2. if (v.size() < n) then n - v.size() spans will have a size of zero.
// 3. span[0].begin() == &v[0]
// 4. span[i].end() == span[i+1].begin() for i in [0..n-1]
// 5. sum of span lengths == v.size()
//
// In order words, the spans cover exactly all the elements of `v` in
// ascending order of positions. Any 2 vectors of the same size are divided
// into `n` spans identically such that corresponding spans have the same size
// and offset from the beginnging.
//
// The constness of the Span::value_type corresponds to the constness of
// v. If v is a const vector, the Span value type is also const.
template <typename VectorLikeType>
auto PartitionEvenly(VectorLikeType&& v, size_t n)
    -> std::vector<decltype(absl::MakeSpan(v))> {
  CHECK_GT(n, 0);
  std::vector<decltype(absl::MakeSpan(v))> result;
  result.reserve(n);

  // This is used for load balancing/sharding. So we want the spans to be as
  // evenly sized as possible. All spans have at least `min_span_size` elements.
  // If v.size() is not evenly divided by n, The first `num_spans_to_grow_by_1`
  // spans each take one extra element.
  const size_t min_span_size = v.size() / n;
  const size_t num_spans_to_grow_by_1 = v.size() % n;
  for (size_t i = 0, current = 0; i < n; ++i) {
    const size_t span_size =
        min_span_size + (i < num_spans_to_grow_by_1 ? 1 : 0);
    result.push_back(
        absl::MakeSpan(span_size ? &v[current] : nullptr, span_size));
    current += span_size;
  }
  return result;
}

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_SPAN_UTIL_H_
