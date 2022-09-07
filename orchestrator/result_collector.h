// Copyright 2022 The SiliFuzz Authors.
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

#ifndef THIRD_PARTY_SILIFUZZ_ORCHESTRATOR_RESULT_COLLECTOR_H_
#define THIRD_PARTY_SILIFUZZ_ORCHESTRATOR_RESULT_COLLECTOR_H_

#include <stdint.h>

#include <memory>
#include <string>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "./orchestrator/binary_log_channel.h"
#include "./proto/corpus_metadata.pb.h"
#include "./runner/driver/runner_driver.h"

namespace silifuzz {

// Execution summary.
struct Summary {
  // Number of snapshots that failed.
  uint64_t num_failed_snapshots = 0;

  // How many times a runner binary was executed.
  uint64_t play_count = 0;

  // Number of runaways detected.
  uint64_t num_runaway_snapshots = 0;
};

// ResultCollector handles execution results produced by worker threads. When
// configured, also logs to the file descriptor passed to its c-tor.
//
// This class is thread-compatible.
class ResultCollector {
 public:
  // If `binary_log_fd_channel` >= 0, will also log each result to the said
  // file descriptor via BinaryLogProducer API. The instance of this class
  // will also take ownership of the FD and close it upon destruction.
  ResultCollector(int binary_log_channel_fd,
                  absl::Time start_time = absl::Now());

  // Processes a single execution result.
  void operator()(const RunnerDriver::RunResult &result);
  // Current execution summary.
  const Summary &summary() const { return summary_; }

  // Logs the current execution summary to stderr. When `always` is true,
  // disables time-based throttling.
  void LogSummary(bool always = false);

  // Logs session summary to binary_log_channel (if any).
  absl::Status LogSessionSummary(const proto::CorpusMetadata &corpus_metadata,
                                 absl::string_view orchestrator_version);

 private:
  std::unique_ptr<BinaryLogProducer> binary_log_producer_;
  absl::Time last_summary_log_time_ = absl::InfinitePast();
  absl::Duration log_interval_ = absl::Seconds(1);
  Summary summary_ = {};
  absl::Time start_time_;
  std::string session_id_;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_ORCHESTRATOR_RESULT_COLLECTOR_H_
