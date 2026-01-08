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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_RESULTS_RECORDER_RESULTS_RECORDER_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_RESULTS_RECORDER_RESULTS_RECORDER_H_

#include <cstddef>
#include <vector>

#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "./fuzzer/hashtest/corpus_config.h"
#include "./fuzzer/hashtest/corpus_stats.h"

namespace silifuzz {

// An interface for recording the results of running HashTest while it is still
// ongoing.
//
// The ordering of methods is the expected order in which they should be
// called.  The only one that can be skipped is RecordUnsupportedPlatform.
// There is not current enforcement of this ordering, but the right to add one
// is reserved.
//
// Subclasses will determine how these values are recorded (ex. Human readable
// output vs a proto).  As such subclasses may only actually record a subset of
// the information provided to this class.
class ResultsRecorder {
 public:
  virtual ~ResultsRecorder() = default;

  /*******************************************************************/
  /********** Called once for each execution of HashTest *************/
  /*******************************************************************/

  // Records the time at which HashTest started.
  virtual void RecordStartInformation(absl::Time start_time) = 0;

  // Records information on the computer being run on.
  virtual void RecordPlatformInfo(absl::string_view hostname,
                                  absl::string_view platform) = 0;

  // Notes that the previously supplied platform is not supported.
  // After this, the expectation is to call FinalizeRecording and exit the
  // program.
  virtual void RecordUnsupportedPlatform() = 0;

  // Records stats about the chip's vector capabilities.
  virtual void RecordChipStats(size_t vector_width, size_t mask_width) = 0;

  // Records information about the configuration provided via commandline flags
  // (or deduced in the case of the seed).
  virtual void RecordConfigurationInformation(
      size_t num_tests, size_t num_inputs, size_t num_repeat,
      size_t num_iterations, size_t batch_size, size_t seed,
      absl::Duration alotted_time, absl::Duration per_corpus_time) = 0;

  // Records the CPUs that will actually be running the HashTests.
  virtual void RecordThreadInformation(absl::Span<const int> cpus) = 0;

  /*******************************************************************/
  /***** Called once for each corpus executed within a HashTest*******/
  /*******************************************************************/

  // Records the configuration of a corpus that is generated.
  virtual void RecordGenerationInformation(const CorpusConfig& config) = 0;

  // Records the size of a generated corpus.
  virtual void RecordCorpusSize(size_t bytes) = 0;

  // Records that end state generation has started.
  virtual void RecordStartEndStateGeneration() = 0;

  // Records the number of times end states could not be reconciled
  virtual void RecordNumFailedEndStateReconciliations(
      size_t failed_reconciliations) = 0;

  // Records the size of the generated end states.
  virtual void RecordEndStateSize(size_t bytes) = 0;

  // Records that test execution has started.
  virtual void RecordStartingTestExecution() = 0;

  // Records the statistics from a single execution of a corpus.
  virtual void RecordCorpusStats(const CorpusConfig& config,
                                 const CorpusStats& stats,
                                 absl::Time corpus_start_time) = 0;

  /*******************************************************************/
  /********** Called once for each execution of HashTest *************/
  /*******************************************************************/

  // Records the final stats of the executions.  If a corpus is run multiple
  // times the stats for all of the runs are expected to be combined into a
  // single CorpusStats object.
  //
  // After this, the expectation is to call FinalizeRecording and exit the
  // program.
  //
  // Expected: corpus_stats[i] == stats for corpus_configs[i]
  virtual void RecordFinalStats(
      const std::vector<CorpusConfig>& corpus_configs,
      const std::vector<CorpusStats>& corpus_stats) = 0;

  // Called after either RecordUnsupportedPlatform or RecordFinalStatus.
  // Further interactions with this interface after calling
  // FinalizeRecording are undefined as the expectation is that the
  // HashTest run ends after this returns.
  virtual void FinalizeRecording() = 0;
};
}  // namespace silifuzz
#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_RESULTS_RECORDER_RESULTS_RECORDER_H_
