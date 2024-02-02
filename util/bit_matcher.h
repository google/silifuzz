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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_BIT_MATCHER_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_BIT_MATCHER_H_

namespace silifuzz {

template <typename T>
struct BitMatcher {
  T mask;
  T bits;

  constexpr bool matches(T insn) const { return (insn & mask) == bits; }
};

template <typename T>
struct RequiredBits {
  BitMatcher<T> pattern;
  BitMatcher<T> expect;
  constexpr bool violates_requirements(T insn) const {
    return pattern.matches(insn) && !expect.matches(insn);
  }
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_BIT_MATCHER_H_
