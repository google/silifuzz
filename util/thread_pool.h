// Copyright 2023 The SiliFuzz Authors.
// Copyright 2017 The Abseil Authors.
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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_THREAD_POOL_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_THREAD_POOL_H_

#include <cstddef>
#include <functional>
#include <queue>
#include <thread>  // NOLINT(build/c++11)
#include <utility>
#include <vector>

#include "absl/base/thread_annotations.h"
#include "absl/functional/any_invocable.h"
#include "absl/synchronization/mutex.h"
#include "./util/checks.h"

namespace silifuzz {

// A simple ThreadPool implementation.
class ThreadPool {
 public:
  explicit ThreadPool(int num_threads) {
    threads_.reserve(num_threads);
    for (int i = 0; i < num_threads; ++i) {
      threads_.emplace_back(&ThreadPool::WorkLoop, this);
    }
  }

  ThreadPool(const ThreadPool &) = delete;
  ThreadPool &operator=(const ThreadPool &) = delete;

  ~ThreadPool() {
    {
      absl::MutexLock lock{&mu_};
      for (size_t i = 0; i < threads_.size(); ++i) {
        queue_.push(nullptr);  // Shutdown signal.
      }
    }
    for (auto &thread : threads_) {
      thread.join();
    }
  }

  // Schedule a function to be run on a ThreadPool thread immediately.
  void Schedule(absl::AnyInvocable<void()> func) {
    CHECK(func != nullptr);
    absl::MutexLock lock{&mu_};
    queue_.emplace(std::move(func));
  }

 private:
  bool WorkAvailable() const ABSL_EXCLUSIVE_LOCKS_REQUIRED(mu_) {
    return !queue_.empty();
  }

  void WorkLoop() {
    while (true) {
      absl::AnyInvocable<void()> func;
      {
        absl::MutexLock lock{&mu_};
        mu_.Await(absl::Condition{this, &ThreadPool::WorkAvailable});
        func = std::move(queue_.front());
        queue_.pop();
      }
      if (func == nullptr) {  // Shutdown signal.
        break;
      }
      func();
    }
  }

  absl::Mutex mu_;
  std::queue<absl::AnyInvocable<void()>> queue_ ABSL_GUARDED_BY(mu_);
  std::vector<std::thread> threads_;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_THREAD_POOL_H_
