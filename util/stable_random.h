// Copyright 2026 The SiliFuzz Authors.
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
#ifndef THIRD_PARTY_SILIFUZZ_UTIL_STABLE_RANDOM_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_STABLE_RANDOM_H_

#include <cstddef>
#include <random>
#include <utility>
#include <vector>

#include "absl/log/check.h"

namespace silifuzz {
namespace tpu {

// For reproducibility, we need to generate random numbers that are stable
// across different platforms and implementations. We cannot use
// std::uniform_int_distribution because it is not guaranteed to be stable.  The
// RNG state can be modified more than once per call. Returns a random size_t in
// the range [lower, upper].
inline size_t StableUniformSizeT(size_t lower, size_t upper,
                                 std::mt19937_64& rng) {
  CHECK_LE(lower, upper);
  size_t range = upper - lower + 1;
  CHECK_GT(range, 0);
  return lower + (rng() % range);
}

// We cannot use std::shuffle because it is not guaranteed to be stable across
// STL implementations.
template <typename T>
void StableShuffle(std::vector<T>& v, std::mt19937_64& rng) {
  for (size_t i = 0; i < v.size(); ++i) {
    size_t j = StableUniformSizeT(i, v.size() - 1, rng);
    std::swap(v[i], v[j]);
  }
}

}  // namespace tpu
}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_STABLE_RANDOM_H_
