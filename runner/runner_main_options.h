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

#ifndef THIRD_PARTY_SILIFUZZ_RUNNER_RUNNER_MAIN_OPTIONS_H_
#define THIRD_PARTY_SILIFUZZ_RUNNER_RUNNER_MAIN_OPTIONS_H_

#include <sys/types.h>

#include <cstddef>
#include <cstdint>

#include "./snap/snap.h"
#include "./util/arch.h"
#include "./util/cpu_id.h"

namespace silifuzz {

// Options passed to RunnerMain().
struct RunnerMainOptions {
  // Returns default options
  static RunnerMainOptions Default() { return {}; }

  // A corpus of Snaps to be executed.
  const SnapCorpus<Host>* corpus;

  // Number of main loop iterations, in each of which a Snap from the corpus is
  // picked an executed. In sequential mode, this is ignored.
  size_t num_iterations = 1000000;

  // Refer to FLAGS_run_time_budget_ms in runner_flags.h for details.
  uint64_t run_time_budget_ms = -1;

  // Random number generator seed. If it is zero, a random seed will be picked.
  uint64_t seed = 0;

  // Pin runner to this CPU unless it is kAnyCPU;
  int cpu = kAnyCPUId;

  // Snapshot to run.
  const char* snap_id = nullptr;

  // Name of the corpus file being run.
  const char* corpus_name = "<unknown>";

  // When true, sends SIGSTOP to self before and after each snap.
  bool enable_tracer = false;

  // PID of the current process.
  pid_t pid = -1;

  // Snap batching:
  //
  // To reduce memory bandwidth consumed by the runner, Snap execution is
  // batched. We group some randomly selected Snaps into a batch. An execution
  // schedule consists of randomly chosen Snaps from the batch is created and
  // the runner executes the Snaps in the schedule sequentially. We use uniform
  // random distributions in both batch and schedule creation. A Snap in the
  // batch is expected to repeated (schedule size/batch size) times on average
  // in the schedule though these is no guarantee that the Snap is executed at
  // all. Increasing this ratio improves memory locality but decreases
  // diversity of the Snaps mix in the schedule. Repeating the same Snap
  // by itself many times may not be interesting from a testing point of view.
  // It also increases the average time to cover the whole corpus. We can
  // improve diversity by increasing the batch size but it will also increase
  // the cache footprints at all levels. Our current corpora contain Snaps that
  // fit in a few 4K pages. So a typical L1 cache cannot hold many Snaps.
  // Ideally we should size the batch to fit in the L2 for maximum performance.
  // To run the runner on all cores of a CPU, the batch size should be set to
  // about the per-core L2 size.
  //
  // We impose maximum a batch size because runner cannot do dynamic
  // allocation.
  //
  // TODO(dougkwan): [perf] These values are chosen by hand arbitrarily. We
  // need to tune the values.
  inline static constexpr uint64_t kDefaultBatchSize = 10;
  inline static constexpr uint64_t kMaxBatchSize = 100;
  inline static constexpr uint64_t kDefaultScheduleSize = 100;

  // Number of Snap in a batch.  Must be between [1, kMaxBatchSize].
  // In sequential mode this is ignored.
  uint64_t batch_size = kDefaultBatchSize;

  // Number of Snap executions in a schedule. Must be greater than 0.
  // In sequential mode this is ignored.
  uint64_t schedule_size = kDefaultScheduleSize;

  // If true, runner sequentially goes through all Snaps once. Batch and
  // schedule sizes in options are ignored. This is used for Snap verification.
  bool sequential_mode = false;

  // The FD of the corpus file, -1 if the FD is not available. The runner may
  // use the FD to create Snap mappings faster.
  int corpus_fd = -1;

  // If true, the end state after snap execution is not checked. Snaps are
  // considered to always end as expected.
  bool skip_end_state_check = false;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_RUNNER_RUNNER_MAIN_OPTIONS_H_
