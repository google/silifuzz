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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_TEST_PARTITION_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_TEST_PARTITION_H_

#include <cstddef>

namespace silifuzz {

struct TestPartition {
  // The first test included in the partition.
  size_t offset;
  // The number of tests in the partition.
  size_t size;
};

// Divide the tests into `num_workers` groups and returns the `index`-th group
// of tests.
TestPartition GetPartition(int index, size_t num_tests, size_t num_workers);
}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_TEST_PARTITION_H_
