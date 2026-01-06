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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_CORPUS_STATS_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_CORPUS_STATS_H_

#include <cstddef>
#include <vector>

#include "absl/time/time.h"
#include "./fuzzer/hashtest/hit.h"

namespace silifuzz {
// The results of running a corpus.
struct CorpusStats {
  // Time consumed generated the test code.
  absl::Duration code_gen_time;
  // Time consumed determining the end state of each test.
  absl::Duration end_state_gen_time;
  // Time consumed running the tests.
  absl::Duration test_time;

  // The hits for this corpus
  std::vector<Hit> hits;

  // The number of different tests that were run.
  size_t distinct_tests = 0;
  // The number of times a test was run.
  size_t test_instance_run = 0;
  // The number of times all the tests iterated.
  size_t test_iteration_run = 0;
  // The number of tests that did not produce the expected end state.
  size_t test_instance_hit = 0;

  CorpusStats& operator+=(const CorpusStats& other) {
    code_gen_time += other.code_gen_time;
    end_state_gen_time += other.end_state_gen_time;
    test_time += other.test_time;
    hits.insert(hits.end(), other.hits.cbegin(), other.hits.cend());
    distinct_tests += other.distinct_tests;
    test_instance_run += other.test_instance_run;
    test_iteration_run += other.test_iteration_run;
    test_instance_hit += other.test_instance_hit;
    return *this;
  }
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_CORPUS_STATS_H_
