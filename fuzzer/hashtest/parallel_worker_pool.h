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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_PARALLEL_WORKER_POOL_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_PARALLEL_WORKER_POOL_H_

#include <cstddef>
#include <functional>
#include <thread>  // NOLINT
#include <vector>

#include "absl/base/thread_annotations.h"
#include "absl/log/check.h"
#include "absl/synchronization/mutex.h"

namespace silifuzz {

// A worker pool that runs statically partitioned work in parallel on multiple
// worker threads.
// This class is not thread safe and its methods should only be invoked by a
// single thread (the "director" thread).
class ParallelWorkerPool {
 public:
  ParallelWorkerPool(size_t num_workers);
  ~ParallelWorkerPool();

  // No copy.
  ParallelWorkerPool(const ParallelWorkerPool&) = delete;
  ParallelWorkerPool& operator=(const ParallelWorkerPool&) = delete;

  // Passes each element of `data` to a corresponding worker thread and invokes
  // `worker_func`. On worker thread "i", `worker_func` will be called with
  // argument data[i]. `data` must have the same number of elements as there are
  // worker threads. The element of `data` recieved by each worker thread should
  // be safe to read and write, since each thread recieves a different element.
  // `worker_func` itself must be thread safe.
  // This function should only be invoked on the director thread.
  // This function will block until the workers finish.
  template <typename T, typename F>
  void DoWork(std::vector<T>& data, F worker_func) {
    CHECK_EQ(data.size(), workers_.size());

    // A wrapper to select the correct chunk of data for each thread.
    // SignalWork() will release the mutex before the worker threads run, and
    // the worker threads will acquire the mutex after they are signaled.
    // This means the assignment to callback_ will happen before the worker
    // threads try to invoke the callback, even though the assignment and use is
    // not explicitly guarded by the mutex.
    callback_ = [&data, &worker_func](int worker_index) {
      worker_func(data[worker_index]);
    };

    // Dispatch the work.
    sync_.SignalWork();

    // At this point, all of the worker threads should have finished so it is
    // safe to modify the callback again.  Aggressively clear the callback to
    // increase visibility of any thread safety issues.
    callback_ = nullptr;
  }

  size_t NumWorkers() const { return workers_.size(); }

 private:
  struct WorkSynchonizer {
    WorkSynchonizer(size_t num_workers)
        : num_workers_(num_workers),
          num_workers_running_(num_workers),
          work_available_(true),
          epoch_(0) {}

    // Called by workers to block until there is work.
    // Returns true if there is pending work.
    // Returns false if the worker should quit.
    [[nodiscard]] bool WaitForWork() ABSL_LOCKS_EXCLUDED(mutex_);

    // Wake the workers up and ask them to do work.
    // Blocks until work is completed.
    // Called by director thread.
    void SignalWork() { SignalWorkers(true); }

    // Wake the workers up and ask them to quit.
    // Called by director thread.
    void SignalDone() { SignalWorkers(false); }

   private:
    // Wake the workers up, either to do work or to quit.
    // Called by the director thread.
    void SignalWorkers(bool work_available) ABSL_LOCKS_EXCLUDED(mutex_);

    // A mutex that guards all the shared state in this struct.
    absl::Mutex mutex_;

    // Where the workers wait.
    absl::CondVar worker_cv_ ABSL_GUARDED_BY(mutex_);

    // Where the director waits.
    absl::CondVar director_cv_ ABSL_GUARDED_BY(mutex_);

    // The number of worker threads.
    const size_t num_workers_;

    // The number of worker threads that have yet to signal they are done.
    // Used to determine when the director thread should be woken up, and also
    // helps the director thread distinguish if a wakeup was spurious.
    size_t num_workers_running_ ABSL_GUARDED_BY(mutex_);

    // Was the worker woken up to work or to quit?
    bool work_available_ ABSL_GUARDED_BY(mutex_);

    // This value will be change each time the workers are woken up.
    // Helps the workers distinguish if the wakeup was spurious, or not.
    unsigned int epoch_ ABSL_GUARDED_BY(mutex_);
  };

  WorkSynchonizer sync_;

  // The worker threads.
  std::vector<std::thread> workers_;

  // The function that will be invoked by each worker.
  // This variable must be treated as read-only while the workers are running.
  std::function<void(int)> callback_;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_PARALLEL_WORKER_POOL_H_
