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

#include <cstdint>

#include "./runner/endspot.h"
#include "./runner/runner_main_options.h"
#include "./snap/snap.h"
#include "./util/arch.h"

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
  EndSpot end_spot;

  // Snap playback outcome code.
  RunSnapOutcome outcome;

  // CPU id (as in getcpu(2)) where the snapshot ran or
  // silifuzz::kUnknownCPUId if it couldn't be determined.
  int64_t cpu_id;
};

// Establishes memory mappings in 'corpus'.
// Takes ownership of 'corpus_fd' and closes it after the corpus is mapped.
// If the corpus is not backed by a file object, 'corpus_fd' may be -1.
// 'corpus_mapping' points to the address where corpus_fd is mapped. This is
// usually identical to the SnapCorpus pointer. This value can be NULL if
// corpus_fd == -1.
void MapCorpus(const SnapCorpus<Host>& corpus, int corpus_fd,
               const void* corpus_mapping);

// Executes 'snap' with 'options' and stores the execution result in 'result'.
// REQUIRES: the runtime environment, including memory mapping used by 'snap'
// must be properly initialized.
//
// We deliberately use a reference instead of returning a RunSnapResult object
// to avoid unnecessary copying.
void RunSnap(const Snap<Host>& snap, const RunnerMainOptions& options,
             RunSnapResult& result);

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
