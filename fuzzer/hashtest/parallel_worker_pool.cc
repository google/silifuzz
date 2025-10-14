// Copyright 2024 The Silifuzz Authors.
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

#include "./fuzzer/hashtest/parallel_worker_pool.h"

#include <cstddef>
#include <thread>  //NOLINT

#include "absl/log/check.h"
#include "absl/synchronization/mutex.h"

namespace silifuzz {

bool ParallelWorkerPool::WorkSynchonizer::WaitForWork() {
  absl::MutexLock lock(mutex_);

  // Store the current epoch on this thread's stack.
  // Releasing/aquiring the mutex inside .wait() should create a barrier that
  // prevents this load from being rematerialized.
  const int epoch_on_entry = epoch_;

  // Last worker to finish notifies the director thread.
  CHECK_GT(num_workers_running_, 0);
  --num_workers_running_;
  if (!num_workers_running_) {
    director_cv_.Signal();
  }

  // Wait until a new epoch begins.
  while (epoch_on_entry == epoch_) {
    worker_cv_.Wait(&mutex_);
  }
  CHECK_NE(epoch_on_entry, epoch_);

  return work_available_;
}

void ParallelWorkerPool::WorkSynchonizer::SignalWorkers(bool work_available) {
  absl::MutexLock lock(mutex_);

  // Newly created worker threads may not have checked in, yet. Wait for them.
  while (num_workers_running_) {
    director_cv_.Wait(&mutex_);
  }
  CHECK(!num_workers_running_);

  // All workers will be running after the notification.
  num_workers_running_ = num_workers_;
  // Modify the epoch to signal this is not a spurious wakeup.
  ++epoch_;
  // Indicate if the workers should keep waiting for signals.
  work_available_ = work_available;
  // Wake up the workers.
  worker_cv_.SignalAll();

  // Wait for the workers to check back in.
  // The workers will not check back in if there isn't any more work.
  if (work_available) {
    while (num_workers_running_) {
      director_cv_.Wait(&mutex_);
    }
    CHECK(!num_workers_running_);
  }
}

ParallelWorkerPool::~ParallelWorkerPool() {
  // Unblock the worker threads and let them die.
  sync_.SignalDone();

  // Wait for each thread to die.
  for (auto& worker : workers_) {
    worker.join();
  }
}

ParallelWorkerPool::ParallelWorkerPool(size_t num_workers)
    : sync_(num_workers) {
  // Create the worker threads.
  for (size_t i = 0; i < num_workers; ++i) {
    workers_.emplace_back(
        [](ParallelWorkerPool* workers, int worker_index) {
          while (workers->sync_.WaitForWork()) {
            // callback_ was set by the director thread before signaling work.
            // It should be treated as read-only by the workers.
            workers->callback_(worker_index);
          }
        },
        this, i);
  }
}

}  // namespace silifuzz
