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

#include "./orchestrator/silifuzz_orchestrator.h"

#include <random>
#include <string>
#include <utility>
#include <vector>

#include "absl/log/check.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "./orchestrator/corpus_util.h"
#include "./runner/driver/runner_driver.h"
#include "./runner/driver/runner_options.h"
#include "./util/checks.h"

namespace silifuzz {

namespace {
// Returns a string representation of StatusOr<RunResult>.
std::string RunResultToDebugString(const RunnerDriver::RunResult &run_result) {
  if (run_result.success()) {
    return "ok";
  }
  switch (run_result.execution_result().code) {
    case RunnerDriver::ExecutionResult::Code::kInternalError:
      return "internal_error";
    case RunnerDriver::ExecutionResult::Code::kSnapshotFailed:
      return "snap_fail";
    default:
      return "unknown";
  }
}
}  // namespace

NextCorpusGenerator::NextCorpusGenerator(int size, bool sequential_mode,
                                         int seed)
    : size_(size),
      sequential_mode_(sequential_mode),
      random_(seed),
      next_index_(0) {
  CHECK_GT(size_, 0);
}

int NextCorpusGenerator::operator()() {
  if (sequential_mode_) {
    return next_index_ < size_ ? next_index_++ : kEndOfStream;
  } else {
    return random_() % size_;
  }
}

// ==================================================================
//
// The main worker thread. Each such thread executes runners with corpora in a
// loop until it is told to stop.
void RunnerThread(CpuExecutionContext* ctx, const RunnerThreadArgs& args) {
  VLOG_INFO(0, "T", args.thread_idx, " started");
  NextCorpusGenerator next_corpus_generator(
      args.corpora->shards.size(), args.runner_options.sequential_mode(),
      args.thread_idx);

  int iteration = 0;
  for (iteration = 0; !ctx->ShouldStop() && !args.cpus.empty(); iteration++) {
    absl::Time start_time = absl::Now();
    absl::Duration time_budget = ctx->deadline() - start_time;
    if (time_budget <= absl::ZeroDuration()) {
      break;
    }
    RunnerOptions runner_options = args.runner_options;
    int target_cpu = args.cpus[iteration % args.cpus.size()];
    runner_options.set_cpu(target_cpu);
    runner_options.set_wall_time_budget(time_budget);
    VLOG_INFO(1, "T", args.thread_idx, " time budget ",
              absl::FormatDuration(time_budget));
    int shard_idx = next_corpus_generator();

    if (shard_idx == NextCorpusGenerator::kEndOfStream) {
      VLOG_INFO(0, "T", args.thread_idx,
                " Reached end of stream in sequential mode");
      break;
    }

    const InMemoryShard &shard = args.corpora->shards[shard_idx];
    RunnerDriver driver =
        RunnerDriver::ReadingRunner(args.runner, shard.file_path, shard.name);
    RunnerDriver::RunResult run_result = driver.Run(runner_options);

    absl::Duration elapsed_time = absl::Now() - start_time;

    std::string log_msg = absl::StrCat(
        "T", args.thread_idx, " cpu: ", target_cpu, " corpus: ", shard.name,
        " time: ", absl::ToInt64Seconds(elapsed_time),
        " exit_status: ", RunResultToDebugString(run_result));
    if (!run_result.execution_result().ok()) {
      LOG_ERROR(log_msg, " ", run_result.execution_result().DebugString());
      if (run_result.postfailure_checksum_status() ==
          RunnerPostfailureChecksumStatus::kMismatch) {
        LOG_ERROR("Snapshot checksum mismatch");
      }
    } else {
      VLOG_INFO(0, log_msg);
    }

    if (!ctx->OfferRunResult(std::move(run_result))) {
      LOG_ERROR(
          "T", args.thread_idx,
          " Result processing queue is stuck, some results won't be logged");
    }
  }

  ctx->Stop();
  VLOG_INFO(0, "T", args.thread_idx, " stopped after ", iteration,
            " iterations");
}

}  // namespace silifuzz
