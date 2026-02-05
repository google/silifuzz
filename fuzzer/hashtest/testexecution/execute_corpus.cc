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

#include "./fuzzer/hashtest/testexecution/execute_corpus.h"

#include <sys/mman.h>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <random>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/log/check.h"
#include "absl/strings/str_cat.h"
#include "absl/synchronization/mutex.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "./fuzzer/hashtest/corpus_config.h"
#include "./fuzzer/hashtest/corpus_stats.h"
#include "./fuzzer/hashtest/entropy.h"
#include "./fuzzer/hashtest/execution_stopper.h"
#include "./fuzzer/hashtest/hit.h"
#include "./fuzzer/hashtest/mxcsr.h"
#include "./fuzzer/hashtest/parallel_worker_pool.h"
#include "./fuzzer/hashtest/runnable_corpus.h"
#include "./fuzzer/hashtest/test_partition.h"
#include "./fuzzer/hashtest/testexecution/hashtest_runner_widgits.h"
#include "./instruction/xed_util.h"
#include "./util/cpu_id.h"
#include "./util/page_util.h"

#ifdef MEMORY_SANITIZER
#include <sanitizer/msan_interface.h>
#endif

namespace silifuzz {

namespace {

// A list of tests to compute end states for.
struct EndStateSubtask {
  absl::Span<const Test> tests;
  absl::Span<EndState> end_states;
};

// Three lists of tests to compute end states for.
struct EndStateTask {
  absl::Span<const Input> inputs;
  EndStateSubtask subtask0;
  EndStateSubtask subtask1;
  EndStateSubtask subtask2;
};

struct TimeEstimator {
  static constexpr double kUpdateInterval = 0.35;
  absl::Time start_time;
  size_t num_run;
  double tests_per_second = 0.0;
  size_t num_run_target;

  // Reset the stat collection, but do not clear the actual estimate.
  // Periodically clearing the stat collection helps us adapt the estimate to
  // changes in the machine's load, etc.
  // Keeping the old estimate lets us start with a reasonable first estimate.
  void Reset(absl::Time now, absl::Time time_limit) {
    start_time = now;
    num_run = 0;
    UpdateRunTarget(now, time_limit);
  }

  // Have we run enough tests that we should check the current time and update
  // the estimate?
  bool ShouldUpdate() { return num_run >= num_run_target; }

  // Update the estimate of how many tests we're running per second and
  // calculate how many tests we should run before the next update.
  void Update(absl::Time now, absl::Time time_limit) {
    tests_per_second =
        num_run / std::max(absl::ToDoubleSeconds(now - start_time), 0.000001);
    UpdateRunTarget(now, time_limit);
  }

  // Approximately how many tests should be run to execute for the duration?
  size_t EstimateNumTests(double duration) {
    // Running a minimum of 100 tests ensures the estimator gets enough data to
    // be reasonably accurate. It also helps deal with the cold start where
    // tests_per_second is 0.
    return static_cast<size_t>(std::max(tests_per_second * duration, 100.0));
  }

  // Set the number of tests runs at which we should check in and update the
  // time estimator.
  void UpdateRunTarget(absl::Time now, absl::Time time_limit) {
    num_run_target = num_run + EstimateNumTests(std::min(
                                   absl::ToDoubleSeconds(time_limit - now),
                                   kUpdateInterval));
  }
};

struct ThreadStats {
  int cpu_id;
  size_t num_run;
  size_t num_failed;
  std::vector<Hit> hits;
  absl::Duration test_duration;

  // A short-term internal stat used to estimate how many tests are being
  // executed per second. May fluctuate if the machine comes under load, etc.
  // Stored in the ThreadStats struct so that subsequent corpus executions can
  // start with an estimate.
  // Note this estimate needs to be done per core because different cores can
  // have different test execution rates for a variety of reasons.
  TimeEstimator time_estimator;
};

EndStateSubtask MakeSubtask(int index, size_t num_inputs, size_t num_workers,
                            absl::Span<const Test> tests,
                            absl::Span<EndState> end_states) {
  TestPartition partition = GetPartition(index, tests.size(), num_workers);

  return {
      .tests = tests.subspan(partition.offset, partition.size),
      .end_states = absl::MakeSpan(end_states)
                        .subspan(partition.offset * num_inputs,
                                 partition.size * num_inputs),
  };
}

void ComputeEndStates(absl::Span<const Test> tests, const TestConfig& config,
                      absl::Span<const Input> inputs,
                      absl::Span<EndState> end_states) {
  CHECK_EQ(tests.size() * inputs.size(), end_states.size());
  for (size_t t = 0; t < tests.size(); ++t) {
    for (size_t i = 0; i < inputs.size(); i++) {
      EntropyBuffer output;
      RunHashTest(tests[t].code, config, inputs[i].entropy, output);
      end_states[t * inputs.size() + i].hash =
          EntropyBufferHash(output, config.vector_width);
    }
  }
}

// Given three end states, select the one that occurs at least twice and return
// true. If all the end states are different, return false.
bool ReconcileEndState(EndState& end_state, const EndState& other1,
                       const EndState& other2) {
  if (end_state.hash == other1.hash) {
    return true;
  }
  if (end_state.hash == other2.hash) {
    return true;
  }
  if (other1.hash == other2.hash) {
    end_state.hash = other1.hash;
    return true;
  }

  // No two of the end states match.
  end_state.SetCouldNotBeComputed();
  return false;
}

// Given three lists of independently computed end states, determine which end
// state we belive is correct and copy it to `end_state`. If it is unclear which
// end state is correct, mark the entry in `end_state` as bad, and skip running
// that test in the future.
// Returns the number of end states that could not be reconciled.
size_t ReconcileEndStates(absl::Span<EndState> end_state,
                          absl::Span<const EndState> other1,
                          absl::Span<const EndState> other2) {
  CHECK_EQ(end_state.size(), other1.size());
  CHECK_EQ(end_state.size(), other2.size());
  size_t fail_count = 0;
  for (size_t i = 0; i < end_state.size(); ++i) {
    if (!ReconcileEndState(end_state[i], other1[i], other2[i])) {
      fail_count++;
    }
  }
  return fail_count;
}

void RunTest(size_t test_index, const Test& test, const TestConfig& config,
             size_t input_index, const Input& input, const EndState& expected,
             ThreadStats& stats) {
  // Run the test.
  EntropyBuffer actual;
  RunHashTest(test.code, config, input.entropy, actual);
  ++stats.num_run;
  ++stats.time_estimator.num_run;

  // Compare the end state.
  bool ok = expected.hash == EntropyBufferHash(actual, config.vector_width);

  if (!ok) {
    ++stats.num_failed;
    stats.hits.push_back({
        .cpu = GetCPUId(),
        .test_index = test_index,
        .test_seed = test.seed,
        .input_index = input_index,
        .input_seed = input.seed,
    });
  }
}

bool RunBatch(absl::Span<const Test> tests, absl::Span<const Input> inputs,
              absl::Span<const EndState> end_states, const RunConfig& config,
              size_t test_offset, absl::Time time_limit, ThreadStats& stats,
              const ExecutionStopper& execution_stopper) {
  // Repeat the batch.
  for (size_t r = 0; r < config.num_repeat; ++r) {
    // Sweep through each input.
    for (size_t i = 0; i < inputs.size(); i++) {
      const Input& input = inputs[i];
      // Sweep through each test in the batch.
      // The point of having a batch size > 1 is that the same test will not be
      // run multiple times in a row.
      for (size_t t = 0; t < tests.size(); ++t) {
        const Test& test = tests[t];
        const EndState& expected = end_states[t * inputs.size() + i];
        if (expected.CouldNotBeComputed()) {
          continue;
        }
        size_t test_index = test_offset + t;
        RunTest(test_index, test, config.test, i, input, expected, stats);
        // This should occur ~4 times a second.
        // reading the clock has overhead / may disrupt the
        // microarchitectural state.
        if (stats.time_estimator.ShouldUpdate()) {
          absl::Time now = absl::Now();
          stats.time_estimator.Update(now, time_limit);
          if (execution_stopper.ShouldStopExecuting()) {
            return false;
          }
          if (now >= time_limit) {
            return false;
          }
        }
      }
    }
  }
  return true;
}

void RunTests(absl::Span<const Test> tests, absl::Span<const Input> inputs,
              absl::Span<const EndState> end_states, const RunConfig& config,
              size_t test_offset, absl::Duration testing_time,
              ThreadStats& stats, const ExecutionStopper& execution_stopper) {
  absl::Time begin_time = absl::Now();
  absl::Time time_limit = begin_time + testing_time;
  stats.time_estimator.Reset(begin_time, time_limit);
  // Iterate until the time limit is reached.
  while (true) {
    // Sweep through the corpus in batches.
    for (size_t g = 0; g < tests.size(); g += config.batch_size) {
      size_t batch_size = std::min(config.batch_size, tests.size() - g);
      if (!RunBatch(
              tests.subspan(g, batch_size), inputs,
              end_states.subspan(g * inputs.size(), batch_size * inputs.size()),
              config, test_offset + g, time_limit, stats, execution_stopper)) {
        stats.test_duration = absl::Now() - begin_time;
        return;
      }
    }
  }
}
}  // namespace

size_t GenerateEndStatesForCorpus(const RunConfig& run_config,
                                  RunnableCorpus& corpus,
                                  ParallelWorkerPool& worker_pool) {
  const size_t num_end_state = corpus.tests.size() * corpus.inputs.size();

  // Redundant sets of end states.
  std::vector<EndState> end_states(num_end_state);
  std::vector<EndState> compare1(num_end_state);
  std::vector<EndState> compare2(num_end_state);

  size_t num_workers = worker_pool.NumWorkers();

  // Partition work.
  std::vector<EndStateTask> tasks(num_workers);
  for (size_t i = 0; i < num_workers; ++i) {
    EndStateTask& task = tasks[i];
    task.inputs = corpus.inputs;

    // For each of the redundant set of end states, compute a different
    // partition on this core.
    // Generating end states is pretty fast. The reason we're doing it on
    // multiple cores is to try and ensure (to the greatest extent possible)
    // that different cores are computing each redudnant version of the end
    // state. This makes it unlikely that the same SDC will corrupt the end
    // state twice. In cases where we are running on fewer than three cores,
    // some of the redundant end states will be computed on the same core.
    task.subtask0 = MakeSubtask(i, corpus.inputs.size(), num_workers,
                                corpus.tests, absl::MakeSpan(end_states));
    task.subtask1 =
        MakeSubtask((i + 1) % num_workers, corpus.inputs.size(), num_workers,
                    corpus.tests, absl::MakeSpan(compare1));
    task.subtask2 =
        MakeSubtask((i + 2) % num_workers, corpus.inputs.size(), num_workers,
                    corpus.tests, absl::MakeSpan(compare2));
  }

  // Execute.
  worker_pool.DoWork(tasks, [&](EndStateTask& task) {
    SetMxcsr(run_config.mxcsr);
    ComputeEndStates(task.subtask0.tests, run_config.test, task.inputs,
                     task.subtask0.end_states);
    ComputeEndStates(task.subtask1.tests, run_config.test, task.inputs,
                     task.subtask1.end_states);
    ComputeEndStates(task.subtask2.tests, run_config.test, task.inputs,
                     task.subtask2.end_states);
  });

  // Try to guess which end states are correct, based on the redundancy.
  size_t bad =
      ReconcileEndStates(absl::MakeSpan(end_states), compare1, compare2);
  corpus.end_states = std::move(end_states);
  return bad;
}

std::vector<PerThreadExecutionStats> ExecuteCorpus(
    const RunnableCorpus& corpus, const RunConfig& run_config,
    absl::Duration testing_time, size_t test_offset,
    const ExecutionStopper& execution_stopper,
    ParallelWorkerPool& worker_pool) {
  std::vector<ThreadStats> stats(worker_pool.NumWorkers());
  // Set MXCSR again here to ensure we are running with the correct value.
  worker_pool.DoWork(stats, [&](ThreadStats& s) {
    s.cpu_id = GetCPUId();
    SetMxcsr(run_config.mxcsr);
    RunTests(corpus.tests, corpus.inputs, corpus.end_states, run_config,
             test_offset, testing_time, s, execution_stopper);
  });
  std::vector<PerThreadExecutionStats> per_thread_stats;
  for (const ThreadStats& s : stats) {
    PerThreadExecutionStats per_thread = {.cpu_id = s.cpu_id,
                                          .testing_duration = s.test_duration,
                                          .tests_run = s.num_run,
                                          .tests_hit = s.num_failed};

    for (const auto& h : s.hits) {
      per_thread.hits.push_back(h);
    }
    per_thread_stats.push_back(per_thread);
  }
  return per_thread_stats;
}

void RunHashTest(void* test, const TestConfig& config,
                 const EntropyBuffer& input, EntropyBuffer& output) {
  if (config.vector_width == 512) {
    RunHashTest512(test, config.num_iterations, &input, &output);
  } else if (config.vector_width == 256) {
    RunHashTest256(test, config.num_iterations, &input, &output);
  } else if (config.vector_width == 128) {
    RunHashTest128(test, config.num_iterations, &input, &output);
  } else {
    CHECK(false) << "Unsupported vector width: " << config.vector_width;
  }
#if defined(MEMORY_SANITIZER)
  __msan_unpoison(output.bytes, output.NumBytes(config.vector_width));
#endif
}

}  // namespace silifuzz
