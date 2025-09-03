// Copyright 2025 The SiliFuzz Authors.
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

#include "./orchestrator/execution_context.h"

#include <vector>

#include "absl/base/log_severity.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"
#include "absl/time/time.h"
#include "./runner/driver/runner_driver.h"
#include "./util/checks.h"

namespace silifuzz {

template <typename RunResultT>
ExecutionContext<RunResultT>::~ExecutionContext() {
  absl::MutexLock l(mu_);
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
template <typename RunResultT>
bool ExecutionContext<RunResultT>::OfferRunResult(
    absl::StatusOr<RunResultT>&& result) {
  absl::MutexLock l(mu_);
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
template <typename RunResultT>
void ExecutionContext<RunResultT>::EventLoop() {
  constexpr absl::Duration kTimeout = absl::Seconds(10);
  while (!ShouldStop()) {
    std::vector<RunResultT> current_results;
    current_results.reserve(num_threads_);
    {
      bool timed_out = mu_.LockWhenWithTimeout(
          absl::Condition(this, &ExecutionContext::ShouldWakeUp), kTimeout);
      VLOG_INFO(2, "Result processor woke up, queue size = ",
                invocation_results_.size(), " due to timeout? = ", timed_out);
      invocation_results_.swap(current_results);
      mu_.unlock();
    }

    ProcessResultQueueImpl(current_results);
  }
}

// Processes the event queue on the calling thread.
// This method needs to be called to process any late-arriving events after
// all worker thread have been joined.
template <typename RunResultT>
void ExecutionContext<RunResultT>::ProcessResultQueue() {
  absl::MutexLock l(mu_);
  ProcessResultQueueImpl(invocation_results_);
  invocation_results_.clear();
}

template <typename RunResultT>
void ExecutionContext<RunResultT>::ProcessResultQueueImpl(
    const std::vector<RunResultT>& results) {
  for (const auto& result : results) {
    if (result_cb_(result)) {
      Stop();
    }
  }
}

// template instantiation for CPU RunnerDriver::RunResult.
template class ExecutionContext<RunnerDriver::RunResult>;

}  // namespace silifuzz
