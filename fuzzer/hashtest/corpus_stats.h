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

#include "absl/container/flat_hash_map.h"
#include "absl/time/time.h"
#include "./fuzzer/hashtest/hit.h"

namespace silifuzz {

// Information about execution of tests on a single thread.
struct PerThreadExecutionStats {
  int cpu_id = 0;
  absl::Duration testing_duration;
  std::vector<Hit> hits;

  // The number of times a test was run.
  size_t tests_run = 0;

  // The number of tests that did not produce the expected end state.
  size_t tests_hit = 0;

  PerThreadExecutionStats& operator+=(const PerThreadExecutionStats& other) {
    testing_duration += other.testing_duration;
    hits.insert(hits.end(), other.hits.cbegin(), other.hits.cend());
    tests_run += other.tests_run;
    tests_hit += other.tests_hit;
    return *this;
  }
};

// The results of running a corpus.
struct CorpusStats {
  // Time consumed generated the test code.
  absl::Duration code_gen_time;
  // Time consumed determining the end state of each test.
  absl::Duration end_state_gen_time;
  // Time consumed running the tests.
  absl::Duration test_time;

  // Maps CPU id to stats for the execution on that cpu core.
  absl::flat_hash_map<int, PerThreadExecutionStats> per_thread_stats;

  CorpusStats& operator+=(const CorpusStats& other) {
    code_gen_time += other.code_gen_time;
    end_state_gen_time += other.end_state_gen_time;
    test_time += other.test_time;
    for (const auto& [cpu_id, thread_stats] : other.per_thread_stats) {
      per_thread_stats[cpu_id] += thread_stats;
    }
    return *this;
  }

  size_t num_runs() const {
    size_t num_runs = 0;
    for (const auto& [_, thread_stats] : per_thread_stats) {
      num_runs += thread_stats.tests_run;
    }
    return num_runs;
  }
  size_t num_hits() const {
    size_t num_hits = 0;
    for (const auto& [_, thread_stats] : per_thread_stats) {
      num_hits += thread_stats.tests_hit;
    }
    return num_hits;
  }
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_CORPUS_STATS_H_
