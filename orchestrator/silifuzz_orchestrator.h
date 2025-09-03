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

#ifndef THIRD_PARTY_SILIFUZZ_ORCHESTRATOR_SILIFUZZ_ORCHESTRATOR_H_
#define THIRD_PARTY_SILIFUZZ_ORCHESTRATOR_SILIFUZZ_ORCHESTRATOR_H_

#include <random>
#include <string>
#include <vector>

#include "./orchestrator/corpus_util.h"
#include "./orchestrator/execution_context.h"
#include "./runner/driver/runner_driver.h"
#include "./runner/driver/runner_options.h"

namespace silifuzz {

// Arguments for RunnerThread.
struct RunnerThreadArgs {
  // Opaque thread identifier. Must be unique.
  int thread_idx = -1;

  // Path to a reading runner.
  std::string runner = "";

  // All available corpora.
  const InMemoryCorpora *corpora = nullptr;

  // CPUs to be scanned by this thread. When the vector is empty, the thread
  // will stop immediately without doing any work.
  std::vector<int> cpus;

  // Additional parameters passed to each runner binary.
  RunnerOptions runner_options = RunnerOptions::Default();
};

// Helper class to generate the next corpus file name.
class NextCorpusGenerator {
 public:
  NextCorpusGenerator(int size, bool sequential_mode, int seed);
  NextCorpusGenerator(const NextCorpusGenerator &) = default;
  NextCorpusGenerator(NextCorpusGenerator &&) = default;
  NextCorpusGenerator &operator=(const NextCorpusGenerator &) = default;
  NextCorpusGenerator &operator=(NextCorpusGenerator &&) = default;
  // Returns the next index corpus file name or "" to stop.
  int operator()();

  static constexpr int kEndOfStream = -1;

 private:
  int size_;
  bool sequential_mode_;
  std::mt19937_64 random_;
  int next_index_;
};

using CpuExecutionContext = ExecutionContext<RunnerDriver::RunResult>;

// Worker thread main function.
void RunnerThread(CpuExecutionContext* ctx, const RunnerThreadArgs& args);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_ORCHESTRATOR_SILIFUZZ_ORCHESTRATOR_H_
