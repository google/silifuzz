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

#include <cstdint>
#include <functional>
#include <random>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"
#include "absl/time/time.h"
#include "./runner/driver/runner_driver.h"
#include "./util/checks.h"
#include "./util/path_util.h"

namespace silifuzz {

namespace {
// Returns a string representation of StatusOr<RunResult>.
std::string RunResultToDebugString(
    const absl::StatusOr<RunnerDriver::RunResult> &run_result_or) {
  if (run_result_or.ok()) {
    if (run_result_or->success()) {
      return "ok";
    } else {
      return "snap_fail";
    }
  } else {
    return "internal_error";
  }
}
}  // namespace

ExecutionContext::~ExecutionContext() {
  absl::MutexLock l(&mu_);
  if (!invocation_results_.empty()) {
    absl::string_view error =
        "The result queue is not empty. Did you call ProcessResultQueue()?";
    if (DEBUG_MODE) {
      LOG_FATAL(error);
    } else {
      LOG_ERROR(error);
    }
  }
}

// Attempts to post RunResult on the result queue. Returns true if the element
// was added, false otherwise.
bool ExecutionContext::OfferRunResult(
    absl::StatusOr<RunnerDriver::RunResult> &&result) {
  absl::MutexLock l(&mu_);
  if (!result.ok()) {
    // Currently, no-Ok() results are not reported to the result queue. It is
    // important however this code executed with mu_ held b/c this allows
    // EventLoop() to wake up and catch deadline events sooner.
    return true;
  }

  // Allow at most 1 result slot per thread.
  if (invocation_results_.size() >= num_threads_) {
    return false;
  }
  invocation_results_.emplace_back(*result);
  return true;
}

// Runs the orchestrator event loop.
// NOTE: This method is not reentrant. Must be called by the main thread.
void ExecutionContext::EventLoop() {
  constexpr absl::Duration kTimeout = absl::Seconds(10);
  while (!ShouldStop()) {
    std::vector<RunnerDriver::RunResult> current_results;
    current_results.reserve(num_threads_);
    {
      bool timed_out = mu_.LockWhenWithTimeout(
          absl::Condition(this, &ExecutionContext::ShouldWakeUp), kTimeout);
      VLOG_INFO(2, "Result processor woke up, queue size = ",
                invocation_results_.size(), " due to timeout? = ", timed_out);
      invocation_results_.swap(current_results);
      mu_.Unlock();
    }

    ProcessResultQueueImpl(current_results);
  }
}

// Processes the event queue on the calling thread.
// This method needs to be called to process any late-arriving events after
// all worker thread have been joined.
void ExecutionContext::ProcessResultQueue() {
  absl::MutexLock l(&mu_);
  ProcessResultQueueImpl(invocation_results_);
  invocation_results_.clear();
}

void ExecutionContext::ProcessResultQueueImpl(
    const std::vector<RunnerDriver::RunResult> &results) {
  for (const auto &result : results) {
    result_cb_(result);
  }
}

std::string NextCorpusGenerator::operator()() {
  if (sequential_mode_) {
    return next_index_ < corpora_.size() ? corpora_[next_index_++] : "";
  } else {
    return corpora_[random_() % corpora_.size()];
  }
}

// The main worker thread. Each such thread executes runners with corpora in a
// loop until it is told to stop.
void RunnerThread(ExecutionContext *ctx, const RunnerThreadArgs &args) {
  VLOG_INFO(0, "T", args.thread_idx, " started");
  NextCorpusGenerator next_corpus_generator(
      args.corpora, args.runner_options.sequential_mode(), args.thread_idx);

  while (!ctx->ShouldStop()) {
    absl::Time start_time = absl::Now();
    absl::Duration time_budget = ctx->deadline() - start_time;
    if (time_budget <= absl::ZeroDuration()) {
      break;
    }
    RunnerOptions runner_options = args.runner_options;
    runner_options.set_wall_time_bugdet(time_budget);
    VLOG_INFO(1, "T", args.thread_idx, " time budget ",
              absl::FormatDuration(time_budget));
    std::string corpus_name = next_corpus_generator();
    if (corpus_name.empty()) {
      VLOG_INFO(0, "T", args.thread_idx,
                " Reached end of stream in sequential mode");
      break;
    }
    RunnerDriver driver = RunnerDriver::ReadingRunner(args.runner, corpus_name);
    absl::StatusOr<RunnerDriver::RunResult> run_result_or =
        driver.Run(runner_options);

    int64_t elapsed_time = absl::ToInt64Seconds(absl::Now() - start_time);

    std::string exit_status = RunResultToDebugString(run_result_or);
    VLOG_INFO(0, "T", args.thread_idx, " corpus: ", Basename(corpus_name),
              " time: ", elapsed_time, " exit_status: ", exit_status);
    if (!run_result_or.ok()) {
      LOG_ERROR("T", args.thread_idx, " corpus: ", Basename(corpus_name),
                " time: ", elapsed_time,
                " error: ", run_result_or.status().message());
    }

    if (!ctx->OfferRunResult(std::move(run_result_or))) {
      LOG_ERROR(
          "T", args.thread_idx,
          " Result processing queue is stuck, some results won't be logged");
    }
  }

  ctx->Stop();
  VLOG_INFO(0, "T", args.thread_idx, " stopped");
}

}  // namespace silifuzz
