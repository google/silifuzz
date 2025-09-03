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

#ifndef THIRD_PARTY_SILIFUZZ_ORCHESTRATOR_EXECUTION_CONTEXT_H_
#define THIRD_PARTY_SILIFUZZ_ORCHESTRATOR_EXECUTION_CONTEXT_H_

#include <atomic>
#include <functional>
#include <vector>

#include "absl/base/thread_annotations.h"
#include "absl/status/statusor.h"
#include "absl/synchronization/mutex.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"

namespace silifuzz {

// Orchestrator execution context.
//
// This class encapsulates the orchestrator event queue (consisting of runner
// execution results). Worker threads publish their results via OfferRunResult()
// in a while (!ShouldStop()) {} loop.
//
// This class is thread-safe.
template <typename RunResultT>
class ExecutionContext {
 public:
  // Callback that is invoked for every RunResult produced by any of the worker
  // threads.
  // The return value of the callback indicates whether the event loop should
  // stop.
  using ResultCallback = std::function<bool(const RunResultT&)>;

  // Constructs an ExecutionContext with the given deadline. Once the deadline
  // is reached ShouldStop() will return true.
  // num_threads is a hint used to size internal data structures.
  // The `result_cb` callback will be invoked by EventLoop() for each RunResult
  // produced by any of the worker threads.
  ExecutionContext(absl::Time deadline, int num_threads,
                   const ResultCallback& result_cb)
      : deadline_(deadline),
        num_threads_(num_threads),
        result_cb_(result_cb),
        mu_(),
        stop_execution_(false),
        invocation_results_() {
    invocation_results_.reserve(num_threads);
  }

  // Not copyable or moveable -- not just a data holder.
  ExecutionContext(const ExecutionContext&) = delete;
  ExecutionContext(ExecutionContext&&) = delete;
  ExecutionContext& operator=(const ExecutionContext&) = delete;
  ExecutionContext& operator=(ExecutionContext&&) = delete;

  ~ExecutionContext();

  // Attempts to post RunResult on the result queue. Returns true if the element
  // was added, false otherwise.
  bool OfferRunResult(absl::StatusOr<RunResultT>&& result);

  // Returns true if the execution should stop.
  bool ShouldStop() const { return stop_execution_ || absl::Now() > deadline_; }

  // Stops the orchestrator.
  // This method is async-signal-safe.
  void Stop() { stop_execution_ = true; }

  // Runs the orchestrator event loop.
  // NOTE: This method is not reentrant. Must be called by the main thread.
  void EventLoop();

  // Processes the event queue on the calling thread.
  // This method needs to be called to process any late-arriving events after
  // all worker thread have been joined.
  void ProcessResultQueue();

  absl::Time deadline() const { return deadline_; }

 private:
  void ProcessResultQueueImpl(const std::vector<RunResultT>& results);

  // EventLoop() helper. Returns true iif the EventLoop() should wake up.
  bool ShouldWakeUp() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mu_) {
    return !invocation_results_.empty() || ShouldStop();
  }

  // C-tor parameters.
  const absl::Time deadline_;
  const int num_threads_;
  ResultCallback result_cb_;

  // Mutex guarding all mutable state of this class.
  mutable absl::Mutex mu_;

  // Global atomic flag to indicate that the orchestrator should stop.
  std::atomic<bool> stop_execution_;

  // A queue of execution results.
  std::vector<RunResultT> invocation_results_ ABSL_GUARDED_BY(mu_);
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_ORCHESTRATOR_EXECUTION_CONTEXT_H_
