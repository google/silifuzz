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

#include "./orchestrator/result_collector.h"

#include <unistd.h>

#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "./common/snapshot_enums.h"
#include "./orchestrator/binary_log_channel.h"
#include "./proto/binary_log_entry.pb.h"
#include "./proto/snapshot_execution_result.pb.h"
#include "./runner/driver/runner_driver.h"
#include "./util/testing/status_macros.h"
#include "./util/testing/status_matchers.h"

namespace silifuzz {
namespace {

using snapshot_types::PlaybackOutcome;

TEST(ResultCollector, Simple) {
  ResultCollector collector(-1, absl::Now());
  collector(RunnerDriver::RunResult::Successful());
  ASSERT_EQ(collector.summary().play_count, 1);
  ASSERT_EQ(collector.summary().num_failed_snapshots, 0);
  RunnerDriver::PlayerResult result = {
      .outcome = PlaybackOutcome::kExecutionMisbehave};
  collector(RunnerDriver::RunResult(result, "snap_id"));
  ASSERT_EQ(collector.summary().play_count, 2);
  ASSERT_EQ(collector.summary().num_failed_snapshots, 1);
}

TEST(ResultCollector, BinaryLogging) {
  int pipefd[2] = {-1, -1};
  ASSERT_EQ(pipe(pipefd), 0);
  {
    ResultCollector collector(pipefd[1], absl::Now());
    collector(RunnerDriver::RunResult::Successful());
    RunnerDriver::PlayerResult result = {
        .outcome = PlaybackOutcome::kExecutionMisbehave};
    collector(RunnerDriver::RunResult(result, "snap_id"));
    // Let collector go out of scope which closes the write end of the pipe.
    // This way the Receive() below does not block if logging misbehaves.
  }
  BinaryLogConsumer consumer(pipefd[0]);
  ASSERT_OK_AND_ASSIGN(proto::BinaryLogEntry fd_log_entry, consumer.Receive());
  ASSERT_EQ(fd_log_entry.snapshot_execution_result().snapshot_id(), "snap_id");
}

}  // namespace

}  // namespace silifuzz
