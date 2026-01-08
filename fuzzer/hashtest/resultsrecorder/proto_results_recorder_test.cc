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

#include <algorithm>
#include <array>
#include <cstddef>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_map.h"
#include "absl/log/check.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "./fuzzer/hashtest/corpus_config.h"
#include "./fuzzer/hashtest/corpus_stats.h"
#include "./fuzzer/hashtest/hashtest_result.pb.h"
#include "./fuzzer/hashtest/hit.h"
#include "./fuzzer/hashtest/testgeneration/version.h"
#include "./util/time_proto_util.h"

namespace silifuzz {
namespace {

constexpr absl::string_view kHostname = "Host";
constexpr absl::string_view kPlatform = "ChipABC";
constexpr size_t kTestsRun = 1000;
constexpr size_t kConfigurationSeed = 0x123;
constexpr size_t kHittingTestSeed = 0xABC;
constexpr size_t kHittingInputSeed = 0xDEF;
constexpr std::array<int, 8> kCpusTested = {0, 1, 2, 3, 4, 5, 6, 7};
constexpr std::array<int, 1> kSuspectedCpus = {3};
constexpr absl::Duration kCodeGenDuration = absl::Milliseconds(10);
constexpr absl::Duration kEndStateGenDuration = absl::Milliseconds(100);
constexpr absl::Duration kTestDuration = absl::Seconds(10);

// Configuration Information
constexpr size_t kNumTests = 100;
constexpr size_t kNumInputs = 10;
constexpr size_t kNumRepeat = 1;
constexpr size_t kNumIterations = 7;
constexpr size_t kBatchSize = 2;
constexpr absl::Duration kAllottedDuration = absl::Seconds(100);
constexpr absl::Duration kPerCorpusTime = absl::Seconds(9);

absl::flat_hash_map<int, PerThreadExecutionStats> CreatePerThreadStats(
    size_t tests_run, const absl::Span<const int> tested_cpus,
    const absl::Span<const int> suspect_cpus) {
  absl::flat_hash_map<int, PerThreadExecutionStats> output;
  for (int cpu : tested_cpus) {
    output[cpu] = {
        .cpu_id = cpu,
        .testing_duration = kTestDuration,
        .hits = {},
        .tests_run = tests_run,
        .tests_hit = 0,
    };
  }
  for (int cpu : suspect_cpus) {
    output[cpu] = {
        .cpu_id = cpu,
        .testing_duration = kTestDuration,
        .hits = std::vector<Hit>({Hit({.cpu = cpu,
                                       .test_seed = kHittingTestSeed,
                                       .input_seed = kHittingInputSeed})}),
        .tests_run = tests_run,
        .tests_hit = 1,
    };
  }
  return output;
}

void InsertPerThreadStats(size_t tests_run,
                          const absl::Span<const int> tested_cpus,
                          const absl::Span<const int> suspect_cpus,
                          proto::CorpusResults& results_out) {
  for (int cpu : tested_cpus) {
    auto* per_thread_results = results_out.add_per_thread_results();
    per_thread_results->set_cpu_id(cpu);
    CHECK_OK(silifuzz::EncodeGoogleApiProto(
        kTestDuration, per_thread_results->mutable_testing_duration()));
    per_thread_results->set_tests_executed(tests_run);
    if (std::find(suspect_cpus.begin(), suspect_cpus.end(), cpu) !=
        suspect_cpus.end()) {
      auto* hit = per_thread_results->add_hits();
      hit->set_test_seed(kHittingTestSeed);
      hit->set_input_seed(kHittingInputSeed);
    }
  }
}
proto::HashTestResult CreateHashTestResultFromConstants() {
  proto::HashTestResult expected;
  expected.set_hostname(kHostname);
  expected.set_platform(kPlatform);
  expected.set_version(GetVersionString());

  proto::ConfigurationInfo* config = expected.mutable_config();
  config->set_threads_attempted(kCpusTested.size());
  config->set_tests_per_corpus(kNumTests);
  config->set_batch_size(kBatchSize);
  config->set_inputs_per_test(kNumInputs);
  config->set_test_input_combination_repeats(kNumRepeat);
  config->set_iterations_per_test(kNumIterations);
  CHECK_OK(silifuzz::EncodeGoogleApiProto(
      kAllottedDuration, config->mutable_allotted_test_time()));
  CHECK_OK(silifuzz::EncodeGoogleApiProto(kPerCorpusTime,
                                          config->mutable_per_corpus_time()));

  config->set_seed(kConfigurationSeed);
  return expected;
}

// An example of how this is expected to be interacted with to generate a
// full proto
TEST(ProtoResultsRecorderTest, SuccessfulEndToEndTest) {
  ProtoResultsRecorder recorder;
  absl::Time start_time = absl::Now();

  recorder.RecordStartInformation(start_time);
  recorder.RecordPlatformInfo(kHostname, kPlatform);

  recorder.RecordConfigurationInformation(
      kNumTests, kNumInputs, kNumRepeat, kNumIterations, kBatchSize,
      kConfigurationSeed, kAllottedDuration, kPerCorpusTime);

  recorder.RecordThreadInformation(kCpusTested);
  CorpusConfig successful_config = {.name = "successful_config"};
  CorpusStats successful_stats = {
      .code_gen_time = kCodeGenDuration,
      .end_state_gen_time = kEndStateGenDuration,
      .test_time = kTestDuration,
      .per_thread_stats = CreatePerThreadStats(kTestsRun, kCpusTested, {})};
  for (int i = 0; i < 10; ++i) {
    recorder.RecordGenerationInformation(successful_config);
    recorder.RecordCorpusSize(1000);
    recorder.RecordStartEndStateGeneration();
    recorder.RecordEndStateSize(1000);
    recorder.RecordStartingTestExecution();
    recorder.RecordNumFailedEndStateReconciliations(0);
    recorder.RecordCorpusStats(successful_config, successful_stats, start_time);
  }

  recorder.RecordFinalStats(std::vector<CorpusConfig>(10, successful_config),
                            std::vector<CorpusStats>(10, successful_stats));
  recorder.FinalizeRecording();

  // Build the expected proto
  proto::HashTestResult expected = CreateHashTestResultFromConstants();
  expected.set_status(proto::HashTestResult::OK);
  CHECK_OK(silifuzz::EncodeGoogleApiProto(start_time,
                                          expected.mutable_testing_started()));
  expected.set_tests_run(kTestsRun * 10 * kCpusTested.size());
  expected.set_tests_failed(0);

  for (int cpu : kCpusTested) {
    expected.add_tested_cpus(cpu);
  }

  for (int i = 0; i < 10; ++i) {
    proto::CorpusResults* corpus_results = expected.add_per_corpus_results();
    corpus_results->set_corpus_configuration(successful_config.name);
    CHECK_OK(silifuzz::EncodeGoogleApiProto(
        kCodeGenDuration, corpus_results->mutable_test_generation_duration()));
    CHECK_OK(silifuzz::EncodeGoogleApiProto(
        kEndStateGenDuration,
        corpus_results->mutable_end_state_generation_duration()));
    CHECK_OK(silifuzz::EncodeGoogleApiProto(
        kTestDuration, corpus_results->mutable_testing_duration()));
    InsertPerThreadStats(kTestsRun, kCpusTested, {}, *corpus_results);
  }
}

// An example of how this is expected to be interacted with to generate a
// full proto and how it works in a failed test
TEST(ProtoResultsRecorderTest, FailuresEndToEndTest) {
  ProtoResultsRecorder recorder;
  absl::Time start_time = absl::Now();

  recorder.RecordStartInformation(start_time);
  recorder.RecordPlatformInfo(kHostname, kPlatform);

  recorder.RecordConfigurationInformation(
      kNumTests, kNumInputs, kNumRepeat, kNumIterations, kBatchSize,
      kConfigurationSeed, kAllottedDuration, kPerCorpusTime);

  recorder.RecordThreadInformation(kCpusTested);
  CorpusConfig successful_config = {.name = "successful_config"};
  CorpusStats successful_stats = {
      .code_gen_time = absl::Milliseconds(10),
      .end_state_gen_time = absl::Milliseconds(100),
      .test_time = absl::Seconds(10),
      .per_thread_stats = CreatePerThreadStats(kTestsRun, kCpusTested, {})};
  std::vector<CorpusConfig> configs = {};
  std::vector<CorpusStats> stats = {};
  for (int i = 0; i < 9; ++i) {
    configs.push_back(successful_config);
    stats.push_back(successful_stats);
    recorder.RecordGenerationInformation(successful_config);
    recorder.RecordCorpusSize(1000);
    recorder.RecordStartEndStateGeneration();
    recorder.RecordEndStateSize(1000);
    recorder.RecordStartingTestExecution();
    recorder.RecordNumFailedEndStateReconciliations(0);
    recorder.RecordCorpusStats(successful_config, successful_stats, start_time);
  }

  CorpusConfig failing_config = {.name = "failing_config"};
  CorpusStats failing_stats = {.code_gen_time = absl::Milliseconds(10),
                               .end_state_gen_time = absl::Milliseconds(100),
                               .test_time = absl::Seconds(10),
                               .per_thread_stats = CreatePerThreadStats(
                                   kTestsRun, kCpusTested, kSuspectedCpus)};

  configs.push_back(failing_config);
  stats.push_back(failing_stats);
  recorder.RecordGenerationInformation(failing_config);
  recorder.RecordCorpusSize(1000);
  recorder.RecordStartEndStateGeneration();
  recorder.RecordEndStateSize(1000);
  recorder.RecordStartingTestExecution();
  recorder.RecordNumFailedEndStateReconciliations(0);
  recorder.RecordCorpusStats(failing_config, failing_stats, start_time);

  recorder.RecordFinalStats(configs, stats);
  recorder.FinalizeRecording();

  // Build the expected proto
  proto::HashTestResult expected = CreateHashTestResultFromConstants();
  expected.set_status(proto::HashTestResult::FAILED);
  CHECK_OK(silifuzz::EncodeGoogleApiProto(start_time,
                                          expected.mutable_testing_started()));
  expected.set_tests_run(kTestsRun * 10 * kCpusTested.size());
  expected.set_tests_failed(1);
  for (int cpu : kCpusTested) {
    expected.add_tested_cpus(cpu);
  }

  for (int cpu : kSuspectedCpus) {
    expected.add_suspected_cpus(cpu);
  }
  for (int i = 0; i < 10; ++i) {
    proto::CorpusResults* corpus_results = expected.add_per_corpus_results();
    corpus_results->set_corpus_configuration(successful_config.name);
    CHECK_OK(silifuzz::EncodeGoogleApiProto(
        kCodeGenDuration, corpus_results->mutable_test_generation_duration()));
    CHECK_OK(silifuzz::EncodeGoogleApiProto(
        kEndStateGenDuration,
        corpus_results->mutable_end_state_generation_duration()));
    CHECK_OK(silifuzz::EncodeGoogleApiProto(
        kTestDuration, corpus_results->mutable_testing_duration()));
    if (i != 9) {
      InsertPerThreadStats(kTestsRun, kCpusTested, {}, *corpus_results);
    } else {
      corpus_results->set_corpus_configuration(failing_config.name);
      InsertPerThreadStats(kTestsRun, kCpusTested, kSuspectedCpus,
                           *corpus_results);
    }
  }
  recorder.FinalizeRecording();
}

TEST(ProtoResultsRecorderTest, UnsupportedPlatformTest) {
  ProtoResultsRecorder recorder;
  absl::Time start_time = absl::Now();

  recorder.RecordStartInformation(start_time);
  recorder.RecordPlatformInfo(kHostname, "ChipDEF");
  recorder.RecordUnsupportedPlatform();
  recorder.FinalizeRecording();

  proto::HashTestResult expected;
  expected.set_platform("ChipDEF");
  expected.set_status(proto::HashTestResult::PLATFORM_NOT_SUPPORTED);
}

}  // namespace
}  // namespace silifuzz
