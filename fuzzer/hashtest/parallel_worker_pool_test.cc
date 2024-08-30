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

#include "./fuzzer/hashtest/parallel_worker_pool.h"

#include <numeric>
#include <vector>

#include "gtest/gtest.h"

namespace silifuzz {

namespace {

TEST(ParallelWorkerPool, SmokeTest) {
  constexpr int kNumThreads = 32;
  ParallelWorkerPool workers(kNumThreads);
  std::vector<int> scratch(kNumThreads);

  // Initialize the data to [0, 1, ..., kNumThreads-1]
  std::iota(std::begin(scratch), std::end(scratch), 0);

  // Double each element 8 times.
  for (int iteration = 0; iteration < 8; ++iteration) {
    workers.DoWork(scratch, [](int& data) { data *= 2; });
  }

  // Check the result.
  for (int i = 0; i < kNumThreads; ++i) {
    EXPECT_EQ(scratch[i], i * 256) << i;
  }
}

}  // namespace

}  // namespace silifuzz
