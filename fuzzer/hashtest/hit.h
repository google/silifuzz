// Copyright 2026 The Silifuzz Authors.
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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_HIT_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_HIT_H_

#include <cstddef>
#include <cstdint>

namespace silifuzz {

// All the information we want to remember about each hit.
struct Hit {
  // CPU the hit occurred on.
  int cpu = 0;
  // A unique identifier in the range [0, num_tests_generated) where
  // num_tests_generated is the total number of tests generated during this
  // invocation of the runner. (Each test has a unique index.)
  size_t test_index = 0;
  // A unique identifier that should be stable between runs, but is not densely
  // packed like test_index.
  uint64_t test_seed = 0;
  // A unique identifier in the range [0, num_inputs_generated) where
  // num_inputs_generated is the total number of inputs generated during this
  // invocation of the runner. (Each input has a unique index.)
  size_t input_index = 0;
  // A unique identifier that should be stable between runs.
  uint64_t input_seed = 0;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_HIT_H_
