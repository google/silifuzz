// Copyright 2024 The Silifuzz Authors.
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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_TESTGENERATION_RAND_UTIL_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_TESTGENERATION_RAND_UTIL_H_

#include <bitset>
#include <cstddef>
#include <initializer_list>
#include <iterator>
#include <random>
#include <vector>

#include "absl/base/attributes.h"
#include "./util/checks.h"

namespace silifuzz {

// Return a random boolean value - 50% true, 50% false.
template <typename Rng>
bool RandomBool(Rng& rng) {
  return std::bernoulli_distribution(0.5)(rng);
}

// With 50% probability, swap the values of `a` and `b`.
template <typename Rng, typename T>
void SometimesSwap(Rng& rng, T& a, T& b) {
  if (RandomBool(rng)) {
    std::swap(a, b);
  }
}

// Return a random element in an iterable range.
template <typename Rng, typename Iter>
auto& ChooseRandomElement(Rng& rng, Iter begin, Iter end) {
  CHECK_GT(std::distance(begin, end), 0);
  std::uniform_int_distribution<size_t> dist(0, std::distance(begin, end) - 1);
  std::advance(begin, dist(rng));
  return *begin;
}

// Return a random element of an iterable type `collection`.
template <typename Rng, typename C>
auto& ChooseRandomElement(Rng& rng,
                          C& collection ABSL_ATTRIBUTE_LIFETIME_BOUND) {
  return ChooseRandomElement(rng, std::begin(collection), std::end(collection));
}

// Template type resolution cannot handle literal lists like "{1, 2, 3}" being
// passed as a parameter unless there is an initializer_list overload.
template <typename Rng, typename T>
T ChooseRandomElement(Rng& rng, std::initializer_list<T> collection) {
  return ChooseRandomElement(rng, std::begin(collection), std::end(collection));
}

// Return the index of a random set bit in `bits`.
// At least one bit must be set.
template <typename Rng, size_t N>
unsigned int ChooseRandomBit(Rng& rng, const std::bitset<N>& bits) {
  CHECK(bits.any());
  unsigned int indexes[N];
  size_t num_bits = 0;
  for (unsigned int i = 0; i < N; ++i) {
    if (bits.test(i)) {
      indexes[num_bits++] = i;
    }
  }
  return indexes[std::uniform_int_distribution<size_t>(0, num_bits - 1)(rng)];
}

// Return the index of a random set bit in `bits` and clear the bit.
// At least one bit must be set.
template <typename Rng, size_t N>
unsigned int PopRandomBit(Rng& rng, std::bitset<N>& bits) {
  unsigned int index = ChooseRandomBit(rng, bits);
  CHECK(bits[index]);
  bits[index] = 0;
  return index;
}

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_TESTGENERATION_RAND_UTIL_H_
