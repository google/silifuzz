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

#include "./fuzzer/hashtest/test_partition.h"

#include <cstddef>

#include "absl/log/check.h"

namespace silifuzz {

TestPartition GetPartition(int index, size_t num_tests, size_t num_workers) {
  CHECK_LT(index, num_workers);
  size_t remainder = num_tests % num_workers;
  size_t tests_in_chunk = num_tests / num_workers;
  if (index < remainder) {
    // The first `remainder` partitions have `tests_in_chunk` + 1 tests.
    return TestPartition{
        .offset = index * (tests_in_chunk + 1),
        .size = tests_in_chunk + 1,
    };
  } else {
    // The rest of the partitions have `tests_in_chunk` tests.
    return TestPartition{
        .offset = index * tests_in_chunk + remainder,
        .size = tests_in_chunk,
    };
  }
}

}  // namespace silifuzz
