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

#include "./fuzzer/hashtest/resultsrecorder/proto_results_recorder.h"

#include <cstddef>
#include <iostream>
#include <vector>

#include "absl/container/flat_hash_set.h"
#include "absl/log/check.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "./fuzzer/hashtest/corpus_config.h"
#include "./fuzzer/hashtest/corpus_stats.h"
#include "./fuzzer/hashtest/hashtest_result.pb.h"
#include "./fuzzer/hashtest/hit.h"
#include "./fuzzer/hashtest/versioning/version.h"
#include "./util/time_proto_util.h"

namespace silifuzz {

ProtoResultsRecorder::ProtoResultsRecorder() {
  results_.set_version(GetVersionString());
}

void ProtoResultsRecorder::RecordStartInformation(absl::Time start_time) {
  CHECK_OK(silifuzz::EncodeGoogleApiProto(start_time,
                                          results_.mutable_testing_started()));
}

void ProtoResultsRecorder::RecordPlatformInfo(absl::string_view hostname,
                                              absl::string_view platform) {
  results_.set_hostname(hostname);
  results_.set_platform(platform);
}

void ProtoResultsRecorder::RecordUnsupportedPlatform() {
  results_.set_status(proto::HashTestResult::PLATFORM_NOT_SUPPORTED);
  results_.set_tests_run(0);
  results_.set_tests_failed(0);
  CHECK_OK(silifuzz::EncodeGoogleApiProto(absl::Now(),
                                          results_.mutable_testing_ended()));
}

void ProtoResultsRecorder::RecordChipStats(size_t vector_width,
                                           size_t mask_width) {}

void ProtoResultsRecorder::RecordConfigurationInformation(
    size_t num_tests, size_t num_inputs, size_t num_repeat,
    size_t num_iterations, size_t batch_size, size_t seed,
    absl::Duration alotted_time, absl::Duration per_corpus_time) {
  proto::ConfigurationInfo* config = results_.mutable_config();
  config->set_tests_per_corpus(num_tests);
  config->set_batch_size(batch_size);
  config->set_inputs_per_test(num_inputs);
  config->set_test_input_combination_repeats(num_repeat);
  config->set_iterations_per_test(num_iterations);
  CHECK_OK(silifuzz::EncodeGoogleApiProto(
      alotted_time, config->mutable_allotted_test_time()));
  CHECK_OK(silifuzz::EncodeGoogleApiProto(per_corpus_time,
                                          config->mutable_per_corpus_time()));
  config->set_seed(seed);
}

void ProtoResultsRecorder::RecordThreadInformation(absl::Span<const int> cpus) {
  results_.mutable_config()->set_threads_attempted(cpus.size());
  for (int cpu : cpus) {
    results_.add_tested_cpus(cpu);
  }
}

void ProtoResultsRecorder::RecordGenerationInformation(
    const CorpusConfig& config) {}

void ProtoResultsRecorder::RecordCorpusSize(size_t bytes) {}

void ProtoResultsRecorder::RecordStartEndStateGeneration() {}

void ProtoResultsRecorder::RecordEndStateSize(size_t bytes) {}

void ProtoResultsRecorder::RecordStartingTestExecution() {}

void ProtoResultsRecorder::RecordNumFailedEndStateReconciliations(
    size_t failed_reconciliations) {}

void ProtoResultsRecorder::RecordCorpusStats(const CorpusConfig& config,
                                             const CorpusStats& stats,
                                             absl::Time corpus_start_time) {
  proto::CorpusResults* corpus_results = results_.add_per_corpus_results();
  corpus_results->set_corpus_configuration(config.name);
  CHECK_OK(silifuzz::EncodeGoogleApiProto(
      stats.code_gen_time, corpus_results->mutable_test_generation_duration()));
  CHECK_OK(silifuzz::EncodeGoogleApiProto(
      stats.end_state_gen_time,
      corpus_results->mutable_end_state_generation_duration()));
  CHECK_OK(silifuzz::EncodeGoogleApiProto(
      stats.test_time, corpus_results->mutable_testing_duration()));

  for (const auto& [_, per_thread] : stats.per_thread_stats) {
    auto* thread_results = corpus_results->add_per_thread_results();
    thread_results->set_cpu_id(per_thread.cpu_id);
    CHECK_OK(silifuzz::EncodeGoogleApiProto(
        per_thread.testing_duration,
        thread_results->mutable_testing_duration()));
    thread_results->set_tests_executed(per_thread.tests_run);
    for (const Hit& h : per_thread.hits) {
      auto* hit_result = thread_results->add_hits();
      hit_result->set_test_seed(h.test_seed);
      hit_result->set_input_seed(h.input_seed);
    }
  }
}

void ProtoResultsRecorder::RecordFinalStats(
    const std::vector<CorpusConfig>& corpus_configs,
    const std::vector<CorpusStats>& corpus_stats) {
  CHECK_OK(silifuzz::EncodeGoogleApiProto(absl::Now(),
                                          results_.mutable_testing_ended()));
  size_t tests_run = 0;
  size_t tests_failed = 0;

  absl::flat_hash_set<int> suspected_cpus;
  for (const CorpusStats& stats : corpus_stats) {
    tests_run += stats.num_runs();
    tests_failed += stats.num_hits();
    for (const auto& [cpu_id, per_thread] : stats.per_thread_stats) {
      if (!per_thread.hits.empty()) {
        suspected_cpus.insert(cpu_id);
      }
    }
  }

  for (const int& suspect_cpu : suspected_cpus) {
    results_.add_suspected_cpus(suspect_cpu);
  }

  results_.set_status(suspected_cpus.empty() ? proto::HashTestResult::OK
                                             : proto::HashTestResult::FAILED);

  results_.set_tests_run(tests_run);
  results_.set_tests_failed(tests_failed);
}

void ProtoResultsRecorder::FinalizeRecording() {
  if (results_.status() == proto::HashTestResult::UNINITIALIZED) {
    if (results_.tests_failed() > 0) {
      results_.set_status(proto::HashTestResult::FAILED);
    } else if (results_.tests_failed() == 0) {
      results_.set_status(proto::HashTestResult::OK);
    }
  }
  results_.SerializeToOstream(&std::cout);
}
}  // namespace silifuzz
