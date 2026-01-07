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

#include <array>
#include <cstddef>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "./fuzzer/hashtest/corpus_config.h"
#include "./fuzzer/hashtest/corpus_stats.h"
#include "./fuzzer/hashtest/hashtest_result.pb.h"
#include "./fuzzer/hashtest/testgeneration/version.h"
#include "./util/time_proto_util.h"

using ::testing::EqualsProto;
using ::testing::proto::Partially;

namespace silifuzz {
namespace {

constexpr absl::string_view kHostname = "Host";
constexpr absl::string_view kPlatform = "ChipABC";
constexpr size_t kTestsRun = 1000;
constexpr size_t kNoTestsFailed = 0;
constexpr size_t kTestsFailed = 10;
constexpr std::array<int, 8> kCpusTested = {0, 1, 2, 3, 4, 5, 6, 7};
constexpr std::array<int, 1> kSuspectedCpus = {3};

// An example of how this is expected to be interacted with to generate a
// full proto
TEST(ProtoResultsRecorderTest, SuccessfulEndToEndTest) {
  ProtoResultsRecorder recorder;
  absl::Time start_time = absl::Now();

  recorder.RecordStartInformation(start_time);
  recorder.RecordPlatformInfo(kHostname, kPlatform);

  recorder.RecordThreadInformation(kCpusTested);
  CorpusConfig successful_config = {.name = "successful_config"};
  CorpusStats success_stats = {
      .code_gen_time = absl::Milliseconds(10),
      .end_state_gen_time = absl::Milliseconds(100),
      .test_time = absl::Seconds(10),
      .hits = {},
      .distinct_tests = kTestsRun,
      .test_instance_run = kTestsRun * kCpusTested.size(),
      .test_iteration_run = 1,
      .test_instance_hit = kNoTestsFailed};
  for (int i = 0; i < 10; ++i) {
    recorder.RecordCorpusStats(success_stats, start_time);
  }

  recorder.RecordFinalStats(std::vector<CorpusConfig>(10, successful_config),
                            std::vector<CorpusStats>(10, success_stats));

  proto::HashTestResult expected;
  expected.set_hostname(kHostname);
  expected.set_platform(kPlatform);
  expected.set_version(GetVersionString());
  expected.set_status(proto::HashTestResult::OK);
  CHECK_OK(silifuzz::EncodeGoogleApiProto(start_time,
                                          expected.mutable_testing_started()));
  expected.set_tests_run(kTestsRun * 10 * kCpusTested.size());
  expected.set_tests_failed(0);
  for (int cpu : kCpusTested) {
    expected.add_tested_cpus(cpu);
  }

  EXPECT_THAT(recorder.GetProto(), Partially(EqualsProto(expected)));
}

// An example of how this is expected to be interacted with to generate a
// full proto and how it works in a failed test
TEST(ProtoResultsRecorderTest, FailuresEndToEndTest) {
  ProtoResultsRecorder recorder;
  absl::Time start_time = absl::Now();

  recorder.RecordStartInformation(start_time);
  recorder.RecordPlatformInfo(kHostname, kPlatform);

  recorder.RecordThreadInformation(kCpusTested);
  CorpusConfig successful_config = {.name = "successful_config"};
  CorpusStats success_stats = {
      .code_gen_time = absl::Milliseconds(10),
      .end_state_gen_time = absl::Milliseconds(100),
      .test_time = absl::Seconds(10),
      .hits = {},
      .distinct_tests = kTestsRun,
      .test_instance_run = kTestsRun * kCpusTested.size(),
      .test_iteration_run = 1,
      .test_instance_hit = kNoTestsFailed};
  std::vector<CorpusConfig> configs = {};
  std::vector<CorpusStats> stats = {};
  for (int i = 0; i < 9; ++i) {
    configs.push_back(successful_config);
    stats.push_back(success_stats);
    recorder.RecordCorpusStats(success_stats, start_time);
  }

  CorpusConfig failing_config = {.name = "failing_config"};
  CorpusStats failing_stats = {
      .code_gen_time = absl::Milliseconds(10),
      .end_state_gen_time = absl::Milliseconds(100),
      .test_time = absl::Seconds(10),
      .hits = {{.cpu = kSuspectedCpus[0]}},
      .distinct_tests = kTestsRun,
      .test_instance_run = kTestsRun * kCpusTested.size(),
      .test_iteration_run = 1,
      .test_instance_hit = kTestsFailed};

  configs.push_back(failing_config);
  stats.push_back(failing_stats);

  recorder.RecordFinalStats(configs, stats);

  proto::HashTestResult expected;
  expected.set_hostname(kHostname);
  expected.set_platform(kPlatform);
  expected.set_version(GetVersionString());
  expected.set_status(proto::HashTestResult::FAILED);
  CHECK_OK(silifuzz::EncodeGoogleApiProto(start_time,
                                          expected.mutable_testing_started()));
  expected.set_tests_run(kTestsRun * 10 * kCpusTested.size());
  expected.set_tests_failed(kTestsFailed);
  for (int cpu : kCpusTested) {
    expected.add_tested_cpus(cpu);
  }

  for (int cpu : kSuspectedCpus) {
    expected.add_suspected_cpus(cpu);
  }

  EXPECT_THAT(recorder.GetProto(), Partially(EqualsProto(expected)));
}

TEST(ProtoResultsRecorderTest, UnsupportedPlatformTest) {
  ProtoResultsRecorder recorder;
  absl::Time start_time = absl::Now();

  recorder.RecordStartInformation(start_time);
  recorder.RecordPlatformInfo(kHostname, "ChipDEF");
  recorder.RecordUnsupportedPlatform();

  proto::HashTestResult expected;
  expected.set_platform("ChipDEF");
  expected.set_status(proto::HashTestResult::PLATFORM_NOT_SUPPORTED);

  EXPECT_THAT(recorder.GetProto(), Partially(EqualsProto(expected)));
}

}  // namespace
}  // namespace silifuzz
