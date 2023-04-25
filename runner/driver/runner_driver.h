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

#ifndef THIRD_PARTY_SILIFUZZ_RUNNER_DRIVER_RUNNER_DRIVER_H_
#define THIRD_PARTY_SILIFUZZ_RUNNER_DRIVER_RUNNER_DRIVER_H_

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "./common/harness_tracer.h"
#include "./common/snapshot.h"
#include "./common/snapshot_enums.h"
#include "./runner/driver/runner_options.h"
#include "./util/checks.h"

namespace silifuzz {

using snapshot_types::PlaybackOutcome;
using snapshot_types::PlaybackResult;

// RunnerDriver wraps a SiliFuzz runner (aka v2 player) binary and provides
// helpers to Play()/Make()/Trace() individual snapshots contained in the
// binary.
//
// This class is thread-compatible.
class RunnerDriver {
 public:
  using PlayerResult = PlaybackResult<Snapshot::EndState>;
  // Represents result of the runner binary invocation. Contains a success bit
  // and an optional PlayerResult representing the result of Snap playback.
  //
  // TODO(ksteuck): [as-needed] Finer-grained error codes needed to handle
  // conditions like "unmappable memory page" or "memory page conflict".
  // TODO(ksteuck): [as-needed] While the runner provides a way to tell if
  // an unexpected syscall was made, this class does not model that state and
  // relies on higher-level StatusOr to capture the fact. If finer-grained
  // result is needed it can be achieved with SECCOMP_RET_TRAP on the runner
  // side + some handling logic here.
  class RunResult {
   public:
    // Constructs a new RunResult from the given `player_result`. The success()
    // value is determined by player_result.outcome == kAsExpected.
    explicit RunResult(const PlayerResult& player_result,
                       absl::string_view snapshot_id = "")
        : success_(player_result.outcome == PlaybackOutcome::kAsExpected),
          player_result_(player_result),
          snapshot_id_(snapshot_id) {}

    // Construct a success()-ful RunResult with no attached player_result.
    static RunResult Successful() { return RunResult(true); }

    // Tests if the execution was successful.
    bool success() const { return success_; }

    // Snapshot ID if there's any associated with the current Result.
    // REQUIRES: !success()
    // Only populated if the runner process reported the snapshot id.
    const std::string& snapshot_id() const {
      CHECK(!success());
      return snapshot_id_;
    }

    // Returns the contained PlayerResult object.
    // REQUIRES !success()
    // PROVIDES player_result.actual_end_state().has_value() == true
    PlayerResult& player_result() {
      CHECK(!success());
      return *player_result_;
    }

    // const version of the above.
    const PlayerResult& player_result() const {
      CHECK(!success());
      return *player_result_;
    }

   private:
    // Constructs a new RunResult with the given success status and no
    // associated `player_result`.
    explicit RunResult(bool success)
        : success_(success), player_result_(std::nullopt) {}

    // Was the execution successful.
    bool success_;

    // Snap play result if one was produced by the runner.
    std::optional<PlayerResult> player_result_;

    // Snapshot id (if any).
    std::string snapshot_id_;
  };

  // Creates a RunnerDriver for a binary with baked-in corpus.
  // The `cleanup` callback will be invoked upon destruction.
  static RunnerDriver BakedRunner(absl::string_view binary_path,
                                  std::function<void()> cleanup = {}) {
    return RunnerDriver(binary_path, "", cleanup);
  }

  // Creates a RunnerDriver for a binary that reads corpus from `corpus_path`.
  // The `cleanup` callback will be invoked upon destruction.
  static RunnerDriver ReadingRunner(absl::string_view binary_path,
                                    absl::string_view corpus_path,
                                    std::function<void()> cleanup = {}) {
    return RunnerDriver(binary_path, corpus_path, cleanup);
  }

  // Movable but not copyable.
  RunnerDriver(const RunnerDriver&) = delete;
  RunnerDriver& operator=(const RunnerDriver&) = delete;
  RunnerDriver(RunnerDriver&& other) = default;
  RunnerDriver& operator=(RunnerDriver&& other) = default;
  ~RunnerDriver() = default;

  // Runs `snap_id` in play mode.
  // REQUIRES snap_id is not empty.
  absl::StatusOr<RunResult> PlayOne(absl::string_view snap_id) const;

  // Runs `snap_id` in make mode (see comments in runner.cc).
  absl::StatusOr<RunResult> MakeOne(absl::string_view snap_id) const;

  // Traces `snap_id` in single-step mode and invokes the provided callback for
  // every instruction of the snapshot.
  absl::StatusOr<RunResult> TraceOne(absl::string_view snap_id,
                                     HarnessTracer::Callback cb) const;

  // Ensures that `snap_id` replays deterministically.
  // REQUIRES snap_id is not empty.
  absl::StatusOr<RunResult> VerifyOneRepeatedly(absl::string_view snap_id,
                                                int num_attempts) const;

  // Runs the runner binary with the provided runner_options.
  //
  // Unlike the *One() family of methods above this is a more generic way of
  // calling the binary that is intended for screening.
  absl::StatusOr<RunResult> Run(const RunnerOptions& runner_options) const;

 private:
  // Wraps the binary at `binary_path`. When `corpus_path` not empty, it will
  // be passed as the last argument to the binary.
  explicit RunnerDriver(absl::string_view binary_path,
                        absl::string_view corpus_path,
                        std::function<void()> cleanup)
      : binary_path_(binary_path),
        corpus_path_(corpus_path),
        cleanup_(this, [cleanup = std::move(cleanup)](RunnerDriver*) mutable {
          if (cleanup) cleanup();
        }) {}

  // Mode of runner binary operation.
  enum class Mode {
    // Default playback mode.
    kPlay,

    // Make mode as defined by --make runner flag.
    kMake,

    // Single-step trace mode. The passed HarnessTracer::Callback instance
    // will be invoked for every instruction of the snap being traced.
    kTrace,
  };

  // Exit codes supported by the runner.
  enum class ExitCode : int {
    kSuccess = 0,
    kFailure = 1,
    kTimeout = 2,
  };
  absl::StatusOr<RunResult> RunImpl(
      const RunnerOptions& runner_options, absl::string_view snap_id = "",
      std::optional<HarnessTracer::Callback> trace_cb = std::nullopt) const;

  absl::StatusOr<RunResult> HandleRunnerOutput(
      absl::string_view runner_stdout, int exit_status,
      absl::string_view snapshot_id = "") const;

  // C-tor parameters.
  std::string binary_path_;
  std::string corpus_path_;

  // Cleanup callback handle. Wraps the user-provided `cleanup` std::function in
  // a container with "at most once" cleanup semantics. When an instance of this
  // class is moved, the handle is moved with it and the moved-from
  // instance's d-tor will not invoke the callback.
  // WARNING: this field must be declared last in RunnerDriver to
  // avoid potential lifetime issues in the callback.
  std::unique_ptr<RunnerDriver, std::function<void(RunnerDriver*)>> cleanup_;
};

// Compiles `snapshot` into a runner binary containing exactly one snap.
// RETURNS RunnerDriver wrapping the runner executable file or a status.
absl::StatusOr<RunnerDriver> RunnerDriverFromSnapshot(
    const Snapshot& snapshot, absl::string_view runner_path);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_RUNNER_DRIVER_RUNNER_DRIVER_H_
