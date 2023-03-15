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

#ifndef THIRD_PARTY_SILIFUZZ_RUNNER_RUNNER_H_
#define THIRD_PARTY_SILIFUZZ_RUNNER_RUNNER_H_

#include <sys/types.h>

#include <cstddef>

#include "./common/snapshot_enums.h"
#include "./snap/snap.h"
#include "./util/cpu_id.h"

namespace silifuzz {

// Snap playback outcome.
// TODO(ksteuck): [test] Add a test to static_assert these values are in sync
// with silifuzz.proto.PlayerResult.Outcome.
enum class RunSnapOutcome : int {
  kAsExpected = 0,        // Snap finished in the expected end state.
  kPlatformMismatch = 1,  // Placeholder, not currently possible with Snap.
  kMemoryMismatch = 2,    // Registers match expected end state but unexpected
                          // memory byte values found after execution.
  kRegisterStateMismatch = 3,  // Unexpected register values found after
                               // execution.
  kEndpointMismatch = 4,       // The endpoint address (%rip) was not the one
                               // expected.
  kExecutionRunaway = 5,       // Execution was a runaway.
  kExecutionMisbehave = 6,     // Execution caused a signal.
};

// Result of RunSnap() after executing a Snap. Captures the EndSpot and the
// corresponding Endpoint (if any) as well as the outcome of the execution.
// NOTE: Unlike the proto::EndState/proto::PlayResult  this struct does not
// contain any of the memory content. The calling code is expected to obtain
// live memory content if needed.
struct RunSnapResult {
  // Contains registers and signal info pertaning to the end_spot reached by
  // by the snapshot.
  snapshot_types::EndSpot end_spot;

  // Snap playback outcome code.
  RunSnapOutcome outcome;

  // CPU id (as in getcpu(2)) where the snapshot ran or
  // silifuzz::kUnknownCPUId if it couldn't be determined.
  int64_t cpu_id;
};

// Options passed to RunnerMain().
struct RunnerMainOptions {
  // A corpus of Snaps to be executed.
  const SnapCorpus* corpus;

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
};

// Establishes memory mappings in 'corpus'.
// Takes ownership of 'corpus_fd' and closes it after the corpus is mapped.
// If the corpus is not backed by a file object, 'corpus_fd' may be -1.
// 'corpus_mapping' points to the address where corpus_fd is mapped. This is
// usually identical to the SnapCorpus pointer. This value can be NULL if
// corpus_fd == -1.
void MapCorpus(const SnapCorpus& corpus, int corpus_fd,
               const void* corpus_mapping);

// Executes 'snap' and stores the execution result in 'result'.
// REQUIRES: the runtime environment, including memory mapping used by 'snap'
// must be properly initialized.
//
// We deliberately use a reference instead of returning a RunSnapResult object
// to avoid unnecessary copying.
void RunSnap(const Snap& snap, RunSnapResult& result);

// Executes Snaps from a corpus according to 'options' and returns an exit code
// that can be passed to _exit(). This is intended to be used for implementing
// the main body of a snap runner.
//
// Typical usage:
//
// int main(...) {
//    RunnerMainOption options;
//    options.corpus = ...
//    ....
//    return RunnerMain(options);
// }
//
int RunnerMain(const RunnerMainOptions& options);

// Similar to RunnerMain() but runs in "sequential" mode. See
// FLAGS_sequential_mode for details.
int RunnerMainSequential(const RunnerMainOptions& options);

// Similar to RunnerMain() but runs in "make" mode. See FLAGS_make for details.
int MakerMain(const RunnerMainOptions& options);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_RUNNER_RUNNER_H_
