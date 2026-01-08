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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_HASHTEST_RUNNER_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_HASHTEST_RUNNER_H_

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <random>
#include <string>
#include <vector>

#include "absl/log/log.h"
#include "absl/synchronization/mutex.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "./fuzzer/hashtest/corpus_config.h"
#include "./fuzzer/hashtest/entropy.h"
#include "./fuzzer/hashtest/hit.h"
#include "./fuzzer/hashtest/run_config.h"
#include "./fuzzer/hashtest/testgeneration/instruction_pool.h"
#include "./fuzzer/hashtest/testgeneration/mxcsr.h"
#include "./fuzzer/hashtest/testgeneration/synthesize_base.h"
#include "./fuzzer/hashtest/testgeneration/synthesize_test.h"

namespace silifuzz {

// Machine instructions for a test.
struct Test {
  // The seed that was used to generate the test.
  // Provides a semi-stable name for the test (the test generation algorithm may
  // be improved from time to time).
  uint64_t seed;

  // The entry point of the test. Jump here to run the test.
  // This is a borrowed reference to memory owned by the Corpus struct.
  void* code;
};

class MemoryMapping {
 public:
  MemoryMapping(void* ptr, size_t allocated_size, size_t used_size)
      : ptr_(ptr), allocated_size_(allocated_size), used_size_(used_size) {}

  ~MemoryMapping();

  // No copy.
  MemoryMapping(const MemoryMapping&) = delete;
  MemoryMapping& operator=(const MemoryMapping&) = delete;

  // Move allowed.
  MemoryMapping(const MemoryMapping&&) = default;
  MemoryMapping& operator=(const MemoryMapping&&) = default;

  void* Ptr() const { return ptr_; }

  size_t AllocatedSize() const { return allocated_size_; }

  void SetUsedSize(size_t used) { used_size_ = used; }
  size_t UsedSize() const { return used_size_; }

 private:
  void* ptr_;
  size_t allocated_size_;
  size_t used_size_;
};

// A collection of tests.
struct Corpus {
  std::vector<Test> tests;
  MemoryMapping mapping;

  size_t MemoryUse() {
    return sizeof(Corpus) + tests.size() * sizeof(Test) + mapping.UsedSize();
  }
};

// We allocate this amount of executable memory per test.
constexpr inline size_t kMaxTestBytes = 2048;

// Created a corpus of the specified size and generate the test seeds.
Corpus AllocateCorpus(std::mt19937_64& rng, size_t num_tests);

// Synthesize the code for each test into `code_buffer`.
// `code_buffer` must be at least `tests`.size() * kMaxTestsBytes bytes large.
// Assumes each test already has a valid seed.
// Returns the amount of memory used by the generated tests.
size_t SynthesizeTests(absl::Span<Test> tests, uint8_t* code_buffer,
                       xed_chip_enum_t chip, const SynthesisConfig& config);

// Do the final steps to make the corpus useable.
void FinalizeCorpus(Corpus& corpus, size_t used_size);

// The expected end state of a test + input.
struct EndState {
  // This field contains the hash of the entropy pool when the test exits.
  // For an individual test, it would be faster to store the entire end state
  // entropy struct and memcmp it. This uses 79x the memory of a hash, however,
  // which can quickly become an issue as the number of tests and inputs
  // increases. Memory bandwidth is also becomes more important for
  // multi-threaded testing. The cost of hashing can easily pay for itself.
  uint64_t hash;

  // It's astronomically unlikely for the hash to be zero, so use this value to
  // mark an end state that could not be computed. We could also store this as a
  // separate bool, but that would double the memory usage.
  void SetCouldNotBeComputed() { hash = 0; }

  bool CouldNotBeComputed() const { return hash == 0; }
};

// For each test and input, compute the end state.
// end_states.size() should be tests.size() * inputs.size().
// For test "t" and input "i", the end state will be stored at index:
// t * inputs.size() + i.
void ComputeEndStates(absl::Span<const Test> tests, const TestConfig& config,
                      absl::Span<const Input> inputs,
                      absl::Span<EndState> end_states);

// Given three lists of independently computed end states, determine which end
// state we belive is correct and copy it to `end_state`. If it is unclear which
// end state is correct, mark the entry in `end_state` as bad, and skip running
// that test in the future.
// Returns the number of end states that could not be reconciled.
size_t ReconcileEndStates(absl::Span<EndState> end_state,
                          absl::Span<const EndState> other1,
                          absl::Span<const EndState> other2);

// An interface for reporting the results of test execution.
struct RunStopper {
  RunStopper(bool printing_allowed = true)
      : printing_allowed(printing_allowed) {}

  // Should stop running tests earlier than we were otherwise planning to?
  bool ShouldStopRunning();

  // Some sort of asynchronous event has occurred. We should stop running tests.
  void StopRunning();

  // Implemented as an atomic rather than protected by the mutex so that we
  // don't need to reason about what happens if we get an async signal while the
  // mutex is being acquired, etc.
  std::atomic<bool> stop_running = false;
  bool printing_allowed;
};

constexpr inline double kUpdateInterval = 0.35;

struct TimeEstimator {
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

// Run each test with each input, and check the end state.
// For test "t" and input "i", the end state will be at index:
//  t * inputs.size() + i.
// Tests will executed in an interleaved order and repeated according to the
// `config`.
void RunTests(absl::Span<const Test> tests, absl::Span<const Input> inputs,
              absl::Span<const EndState> end_states, const RunConfig& config,
              size_t test_offset, absl::Duration testing_time,
              ThreadStats& stats, RunStopper& result);

// Internal function, exported for testing.
void RunHashTest(void* test, const TestConfig& config,
                 const EntropyBuffer& input, EntropyBuffer& output);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_HASHTEST_RUNNER_H_
