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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_WEIGHTED_CHOOSE_ONE_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_WEIGHTED_CHOOSE_ONE_H_

#include <random>

namespace silifuzz {

// A weighted callback.
template <typename F>
struct WeightedChoice {
  int weight;
  F callback;
};

namespace internal {

template <typename F>
inline int TotalWeight(WeightedChoice<F>& current) {
  return current.weight;
}

template <typename F, typename... Others>
inline int TotalWeight(WeightedChoice<F>& current, Others... others) {
  return current.weight + TotalWeight(others...);
}

template <typename F>
inline auto WeightedChooseOneDispatch(int choice, WeightedChoice<F>& current) {
  return current.callback();
}

template <typename F, typename... Others>
inline auto WeightedChooseOneDispatch(int choice, WeightedChoice<F>& current,
                                      Others... others) {
  if (choice < current.weight) {
    return current.callback();
  } else {
    return WeightedChooseOneDispatch(choice - current.weight, others...);
  }
}

}  // namespace internal

// Invoke one of several callbacks once, with the probability of each callback
// being proportional to its weight.
//
// The weights must be non-negative integers.
//
// Example:
//   WeightedChooseOne(rng,
//                     WeightedChoice{1, [&]() { /* a */ }},
//                     WeightedChoice{1, [&]() { /* b */ }},
//                     WeightedChoice{1, [&]() { /* c */ }});
//
// This will invoke one of the callbacks with probability 1/3 each.
// Essentially this is switch statement that chooses the case randomly.
// This API is a little awkward. It is designed so that that everything can be
// inlined and the generated code does not need to do any sort of memory
// allocation - even when using lambdas with captures.
template <typename Rng, typename... Choices>
auto WeightedChooseOne(Rng& rng, Choices... choices) {
  int total = internal::TotalWeight(choices...);
  int choice = std::uniform_int_distribution<int>(0, total - 1)(rng);
  return internal::WeightedChooseOneDispatch(choice, choices...);
}

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_WEIGHTED_CHOOSE_ONE_H_
