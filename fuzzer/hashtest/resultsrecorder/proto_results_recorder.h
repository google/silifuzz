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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_RESULTSRECORDER_PROTO_RESULTS_RECORDER_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_RESULTSRECORDER_PROTO_RESULTS_RECORDER_H_

#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "./fuzzer/hashtest/corpus_config.h"
#include "./fuzzer/hashtest/corpus_stats.h"
#include "./fuzzer/hashtest/hashtest_result.pb.h"
#include "./fuzzer/hashtest/resultsrecorder/results_recorder.h"
#include "./fuzzer/hashtest/testgeneration/version.h"

namespace silifuzz {
class ProtoResultsRecorder final : public ResultsRecorder {
 public:
  ProtoResultsRecorder();
  virtual ~ProtoResultsRecorder() = default;
  void RecordStartInformation(absl::Time start_time) override;
  void RecordPlatformInfo(absl::string_view hostname,
                          absl::string_view platform) override;

  void RecordUnsupportedPlatform() override;

  void RecordChipStats(size_t vector_width, size_t mask_width) override;

  void RecordConfigurationInformation(size_t num_tests, size_t num_inputs,
                                      size_t num_repeat, size_t num_iterations,
                                      size_t batch_size, size_t seed) override;

  void RecordThreadInformation(absl::Span<const int> cpus) override;

  void RecordGenerationInformation(const CorpusConfig& config) override;
  void RecordCorpusSize(size_t bytes) override;
  void RecordStartEndStateGeneration() override;
  void RecordNumFailedEndStateReconciliations(
      size_t failed_reconciliations) override;
  void RecordEndStateSize(size_t bytes) override;
  void RecordStartingTestExecution() override;

  void RecordCorpusStats(const CorpusStats& stats,
                         absl::Time corpus_start_time) override;
  void RecordFinalStats(const std::vector<CorpusConfig>& corpus_configs,
                        const std::vector<CorpusStats>& corpus_stats) override;

  void FinalizeRecording() override;

  // Visible For Test
  const proto::HashTestResult& GetProto() { return results_; }

 private:
  proto::HashTestResult results_;
};
}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_RESULTSRECORDER_PROTO_RESULTS_RECORDER_H_
