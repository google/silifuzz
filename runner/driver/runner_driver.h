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

#include <sys/resource.h>

#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./common/harness_tracer.h"
#include "./common/snapshot.h"
#include "./common/snapshot_enums.h"
#include "./runner/driver/runner_options.h"
#include "./util/checks.h"
#include "./util/cpu_id.h"
#include "./util/subprocess.h"

namespace silifuzz {

using snapshot_types::PlaybackOutcome;
using snapshot_types::PlaybackResult;
using snapshot_types::RunnerPostfailureChecksumStatus;

class RunResultPeer;

// RunnerDriver wraps a SiliFuzz runner (aka v2 player) binary and provides
// helpers to Play()/Make()/Trace() individual snapshots contained in the
// binary.
//
// This class is thread-compatible.
class RunnerDriver {
 public:
  struct ExecutionResult {
    using Code = snapshot_types::RunnerExecutionStatusCode;
    Code code;
    std::string message;

    bool ok() const { return code == Code::kOk; }
    static ExecutionResult OkResult() { return ExecutionResult{Code::kOk, ""}; }
    static ExecutionResult InternalError(absl::string_view message) {
      return ExecutionResult{Code::kInternalError, std::string(message)};
    }
    static ExecutionResult SnapshotFailed(absl::string_view message) {
      return ExecutionResult{Code::kSnapshotFailed, std::string(message)};
    }

    std::string DebugString() const {
      return absl::StrCat("ExecutionResult {code:", code, " error:", message,
                          "}");
    }
  };
  using PlayerResult = PlaybackResult<Snapshot::EndState>;

  // Represents result of the runner binary invocation. Contains a success bit
  // and an optional PlayerResult representing the result of Snap playback.
  //
  // TODO(ksteuck): [as-needed] While the runner provides a way to tell if
  // an unexpected syscall was made, this class does not model that state and
  // relies on higher-level StatusOr to capture the fact. If finer-grained
  // result is needed it can be achieved with SECCOMP_RET_TRAP on the runner
  // side + some handling logic here.
  class RunResult {
   public:
    // Construct a success()-ful RunResult with no attached player_result.
    static RunResult Successful(const struct rusage& rusage) {
      return RunResult(ExecutionResult::OkResult(), std::nullopt, rusage);
    }

    static RunResult FromExecutionResult(
        const ExecutionResult& execution_result, const struct rusage& rusage) {
      return RunResult(execution_result, std::nullopt, rusage);
    }

    static RunResult InternalError(absl::string_view error_message) {
      return RunResult(ExecutionResult::InternalError(error_message),
                       std::nullopt, {});
    }

    // Tests if the execution was successful.
    bool success() const { return success_; }

    // Snapshot ID if there's any associated with the current Result.
    // REQUIRES: !success()
    // Only populated if the runner process reported the snapshot id.
    const std::string& failed_snapshot_id() const {
      CHECK(!success());
      return snapshot_id_;
    }

    bool has_failed_player_result() const { return player_result_.has_value(); }

    // Returns the contained PlayerResult object.
    // REQUIRES has_failed_player_result() == true.
    // PROVIDES player_result.actual_end_state().has_value() == true
    const PlayerResult& failed_player_result() const {
      CHECK(has_failed_player_result());
      return *player_result_;
    }

    // Information about the resource usage of the run.
    const struct rusage& rusage() const { return rusage_; }

    // Returns the contained ExecutionResult object.
    const ExecutionResult& execution_result() const {
      return execution_result_;
    }

    // Returns the status of the post-failure checksum validation.
    // REQUIRES !success()
    RunnerPostfailureChecksumStatus postfailure_checksum_status() const {
      CHECK(!success());
      return postfailure_checksum_status_;
    }

   private:
    RunResult(const ExecutionResult& execution_result,
              const std::optional<PlayerResult>& player_result,
              const struct rusage& rusage, absl::string_view snapshot_id = "",
              RunnerPostfailureChecksumStatus postfailure_checksum_status =
                  RunnerPostfailureChecksumStatus::kNotChecked)
        : success_(execution_result.ok()),
          player_result_(player_result),
          snapshot_id_(snapshot_id),
          rusage_(rusage),
          execution_result_(execution_result),
          postfailure_checksum_status_(postfailure_checksum_status) {
      // Cross check that overall execution result matches player outcome.
      CHECK_EQ(execution_result.ok(), success_);
    }

    friend class RunnerDriver;
    friend class RunResultPeer;

    // Was the execution successful.
    bool success_;

    // Snap play result if one was produced by the runner.
    std::optional<PlayerResult> player_result_;

    // Snapshot id (if any).
    std::string snapshot_id_;

    struct rusage rusage_;

    ExecutionResult execution_result_;

    RunnerPostfailureChecksumStatus postfailure_checksum_status_;
  };

  // Creates a RunnerDriver for a binary that reads corpus from `corpus_path`.
  // The runner will display the corpus name as `corpus_name`. If `corpus_name`
  // is empty, it will use `corpus_path` instead. This allows us to pass a
  // corpus either as a file or as a memfd with a meaningful name.
  // The `cleanup` callback will be invoked upon destruction.
  static RunnerDriver ReadingRunner(absl::string_view binary_path,
                                    absl::string_view corpus_path,
                                    absl::string_view corpus_name = "",
                                    std::function<void()> cleanup = {}) {
    return RunnerDriver(binary_path, corpus_path, corpus_name, cleanup);
  }

  // Movable but not copyable.
  RunnerDriver(const RunnerDriver&) = delete;
  RunnerDriver& operator=(const RunnerDriver&) = delete;
  RunnerDriver(RunnerDriver&& other) = default;
  RunnerDriver& operator=(RunnerDriver&& other) = default;
  ~RunnerDriver() = default;

  // Runs `snap_id` in play mode.
  // REQUIRES snap_id is not empty.
  RunResult PlayOne(absl::string_view snap_id, int cpu = kAnyCPUId) const;

  // Runs `snap_id` in make mode (see comments in runner.cc).
  // During making, up to 'max_pages_to_add' pages are added to the snapshot.
  // Making fails if more pages are required. If 'max_pages_to_add' is 0,
  // the runner does not add any new page and the caller of the runner driver
  // need to add necessary pages in the making process.
  RunResult MakeOne(absl::string_view snap_id, size_t max_pages_to_add = 0,
                    int cpu = kAnyCPUId) const;

  // Traces `snap_id` in single-step mode and invokes the provided callback for
  // every instruction of the snapshot. This runs the snapshot `num_iterations`
  // times.
  RunResult TraceOne(absl::string_view snap_id, HarnessTracer::Callback cb,
                     size_t num_iterations = 1, int cpu = kAnyCPUId) const;

  // Ensures that `snap_id` replays deterministically.
  // REQUIRES snap_id is not empty.
  RunResult VerifyOneRepeatedly(absl::string_view snap_id, int num_attempts,
                                int cpu = kAnyCPUId) const;

  // Runs the runner binary with the provided runner_options.
  //
  // Unlike the *One() family of methods above this is a more generic way of
  // calling the binary that is intended for screening.
  RunResult Run(const RunnerOptions& runner_options) const;

 private:
  // Wraps the binary at `binary_path`. When `corpus_path` not empty, it will
  // be passed as the last argument to the binary.
  RunnerDriver(absl::string_view binary_path, absl::string_view corpus_path,
               absl::string_view corpus_name, std::function<void()> cleanup)
      : binary_path_(binary_path),
        corpus_path_(corpus_path),
        corpus_name_(corpus_name),
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
  RunResult RunImpl(
      const RunnerOptions& runner_options, absl::string_view snap_id = "",
      std::optional<HarnessTracer::Callback> trace_cb = std::nullopt) const;

  RunResult HandleRunnerOutput(absl::string_view runner_stdout,
                               const ProcessInfo& info,
                               absl::string_view snapshot_id = "") const;

  // C-tor parameters.
  std::string binary_path_;
  std::string corpus_path_;
  std::string corpus_name_;

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
