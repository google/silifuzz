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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_TESTEXECUTION_EXECUTE_CORPUS_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_TESTEXECUTION_EXECUTE_CORPUS_H_

#include <cstddef>

#include "absl/container/flat_hash_map.h"
#include "absl/time/time.h"
#include "./fuzzer/hashtest/corpus_stats.h"
#include "./fuzzer/hashtest/execution_stopper.h"
#include "./fuzzer/hashtest/parallel_worker_pool.h"
#include "./fuzzer/hashtest/run_config.h"
#include "./fuzzer/hashtest/runnable_corpus.h"

namespace silifuzz {

// For each test and input, compute an end state.
// We compute each end state 3x, and choose an end state that occurred more than
// once. If all the end states are different, the end state is marked as bad and
// that test+input combination will be skipped when running tests.
// Returns the number of unreconcilable end states.
size_t GenerateEndStatesForCorpus(const RunConfig& run_config,
                                  RunnableCorpus& corpus,
                                  ParallelWorkerPool& worker_pool);

// TODO(danieljsnyder): Remove test_offset all that it does is track that a test was
// the n'th test generated across all configs.
// TODO(danieljsnyder): Should execution_stopper be non-const since it can be
// changed by another thread?
absl::flat_hash_map<int, PerThreadExecutionStats> ExecuteCorpus(
    const RunnableCorpus& corpus, const RunConfig& run_config,
    absl::Duration testing_time, size_t test_offset,
    const ExecutionStopper& execution_stopper, ParallelWorkerPool& worker_pool);

// Internal function, exported for testing.
void RunHashTest(void* test, const TestConfig& config,
                 const EntropyBuffer& input, EntropyBuffer& output);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_TESTEXECUTION_EXECUTE_CORPUS_H_
