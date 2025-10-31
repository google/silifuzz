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

#include "./runner/driver/runner_driver.h"

#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "google/protobuf/text_format.h"
#include "./common/harness_tracer.h"
#include "./common/snapshot.h"
#include "./player/player_result_proto.h"
#include "./proto/snapshot_execution_result.pb.h"
#include "./runner/driver/runner_options.h"
#include "./snap/gen/relocatable_snap_generator.h"
#include "./util/arch.h"
#include "./util/byte_io.h"
#include "./util/checks.h"
#include "./util/cpu_id.h"
#include "./util/mmapped_memory_ptr.h"
#include "./util/subprocess.h"

namespace silifuzz {

RunnerDriver::RunResult RunnerDriver::PlayOne(absl::string_view snap_id,
                                              int cpu) const {
  CHECK(!snap_id.empty());
  return RunImpl(RunnerOptions::PlayOptions(snap_id, cpu), snap_id);
}

RunnerDriver::RunResult RunnerDriver::MakeOne(
    absl::string_view snap_id, size_t max_pages_to_add, int cpu,
    absl::Duration cpu_time_budget) const {
  CHECK(!snap_id.empty());
  return RunImpl(RunnerOptions::MakeOptions(snap_id, max_pages_to_add, cpu,
                                            cpu_time_budget),
                 snap_id);
}

RunnerDriver::RunResult RunnerDriver::TraceOne(absl::string_view snap_id,
                                               HarnessTracer::Callback cb,
                                               size_t num_iterations,
                                               int cpu) const {
  CHECK(!snap_id.empty());
  return RunImpl(RunnerOptions::TraceOptions(snap_id, num_iterations, cpu),
                 snap_id, cb);
}

RunnerDriver::RunResult RunnerDriver::VerifyOneRepeatedly(
    absl::string_view snap_id, int num_attempts, int cpu,
    absl::Duration cpu_time_budget) const {
  CHECK(!snap_id.empty());
  auto opts = RunnerOptions::VerifyOptions(snap_id, cpu, cpu_time_budget);
  for (int i = 0; i < num_attempts - 1; ++i) {
    if (auto result = RunImpl(opts, snap_id); !result.success()) {
      return result;
    }
  }
  return RunImpl(opts, snap_id);
}

RunnerDriver::RunResult RunnerDriver::Run(
    const RunnerOptions& runner_options) const {
  return RunImpl(runner_options);
}

// Generic entry point for all methods that need to execute the runner binary
// and handle its output.
RunnerDriver::RunResult RunnerDriver::RunImpl(
    const RunnerOptions& runner_options, absl::string_view snap_id,
    std::optional<HarnessTracer::Callback> trace_cb) const {
  std::vector<std::string> argv = {binary_path_};
  Subprocess::Options options = Subprocess::Options::Default();
  options.DisableAslr(runner_options.disable_aslr())
      .SetParentDeathSignal(SIGKILL);
  if (auto cpu_time_budget = runner_options.cpu_time_budget();
      cpu_time_budget != absl::InfiniteDuration()) {
    // Soft-cap at the runner_options.cpu_time_budget, hard-cap +1 second
    // to give the process a chance to exit gracefully.
    options.SetRLimit(RLIMIT_CPU, absl::ToInt64Seconds(cpu_time_budget),
                      absl::ToInt64Seconds(cpu_time_budget + absl::Seconds(1)));
  }
  if (auto wall_time_budget = runner_options.wall_time_budget();
      wall_time_budget != absl::InfiniteDuration()) {
    options.SetITimer(ITIMER_REAL, wall_time_budget);
  }
  if (runner_options.cpu() != kAnyCPUId) {
    argv.push_back(absl::StrCat("--cpu=", runner_options.cpu()));
  }
  if (runner_options.sequential_mode()) {
    argv.push_back("--sequential_mode");
  }
  // Pass-thru VLOG levels to the runner.
  if (VLOG_IS_ON(1)) {
    argv.push_back("--v=1");
  } else if (VLOG_IS_ON(2)) {
    argv.push_back("--v=2");
  }
  if (!corpus_name_.empty()) {
    argv.push_back(absl::StrCat("--corpus_name=", corpus_name_));
  }
  for (const std::string& extra : runner_options.extra_argv()) {
    argv.push_back(extra);
  }

  if (!corpus_path_.empty()) {
    argv.push_back(corpus_path_);
  }

  if (runner_options.map_stderr_to_dev_null()) {
    options.MapStderr(Subprocess::kMapToDevNull);
  }

  Subprocess runner_proc(options);
  if (auto s = runner_proc.Start(argv); !s.ok()) {
    return RunResult::InternalError(s.message());
  }

  std::unique_ptr<HarnessTracer> tracer = nullptr;
  if (trace_cb.has_value()) {
    tracer = std::make_unique<HarnessTracer>(
        runner_proc.pid(), HarnessTracer::Mode::kSingleStep, trace_cb.value());
    tracer->Attach();
  }

  std::string runner_stdout;
  ProcessInfo info = runner_proc.Communicate(&runner_stdout);
  std::optional<ProcessInfo> tracee_info;
  if (tracer != nullptr) {
    tracee_info = tracer->Join();
    // Because there's a race between the tracer and the Subprocess we need to
    // grab the exit status from the whoever calls waitpid first.
    if (tracee_info.has_value()) {
      info = tracee_info.value();
    }
  }
  return HandleRunnerOutput(runner_stdout, info, snap_id);
}

RunnerDriver::RunResult RunnerDriver::HandleRunnerOutput(
    absl::string_view runner_stdout, const ProcessInfo& info,
    absl::string_view snapshot_id) const {
  VLOG_INFO(3, absl::StrCat("Snapshot [", snapshot_id,
                            "] runner exit status = ", info.status));
  if (WIFSIGNALED(info.status)) {
    int sig_num = WTERMSIG(info.status);
    if (sig_num == SIGINT) {
      // Assume this was sent from the controlling terminal and just pretend
      // everything is fine.
      return RunResult::Successful(info.rusage);
    }
    if (sig_num == SIGSYS) {
      // The process died with SIGSYS because an unexpected syscall was made.
      return RunResult::InternalError("Snapshot made a syscall");
    }
    return RunResult::InternalError(
        absl::StrCat("Runner killed by signal ", sig_num));
  }
  if (WIFEXITED(info.status)) {
    // Successful execution
    ExitCode exit_code = static_cast<ExitCode>(WEXITSTATUS(info.status));
    if (exit_code == ExitCode::kSuccess) {
      return RunResult::Successful(info.rusage);
    }
    // Graceful shutdown due to timeout. Convert this to success with the
    // caveat that this can hide runners that are not making progress.
    //
    // TODO(ksteuck): [as-needed] Change the API of the runner to provide some
    // sort of heartbeat signal (via a new FD, shared memory or the existing
    // stdout logging). The idea is that instead of blindly converting exit
    // code 2 into Successful() we should also be checking that some progress
    // was made.
    if (exit_code == ExitCode::kTimeout && snapshot_id.empty()) {
      VLOG_INFO(1, "Runner process timed out");
      return RunResult::Successful(info.rusage);
    }
    google::protobuf::TextFormat::Parser parser;
    proto::RunnerOutput runner_output_proto;
    if (!parser.ParseFromString(runner_stdout, &runner_output_proto)) {
      return RunResult::InternalError(absl::StrCat(
          "couldn't parse [", runner_stdout,
          "] as proto::RunnerOutput. Exit status = ", info.status));
    }

    if (!runner_output_proto.has_execution_result()) {
      return RunResult::InternalError("Missing required execution_result");
    }
    ExecutionResult execution_result = ExecutionResult{
        .code = static_cast<ExecutionResult::Code>(
            runner_output_proto.execution_result().code()),
        .message = runner_output_proto.execution_result().msg(),
    };

    if (!runner_output_proto.has_failed_snapshot_execution()) {
      return RunResult::FromExecutionResult(execution_result, info.rusage);
    }

    const proto::SnapshotExecutionResult& exec_result_proto =
        runner_output_proto.failed_snapshot_execution();
    if (!snapshot_id.empty() &&
        exec_result_proto.snapshot_id() != snapshot_id) {
      return RunResult::InternalError(absl::StrCat(
          "Runner misbehaved: got id [", exec_result_proto.snapshot_id(),
          "] expected ", snapshot_id, ". Exit status = ", info.status));
    }
    absl::StatusOr<PlayerResult> player_result =
        PlayerResultProto::FromProto(exec_result_proto.player_result());
    if (!player_result.status().ok()) {
      return RunResult::InternalError(absl::StrCat(
          "PlayerResultProto::FromProto: ", player_result.status().message()));
    }
    if (!player_result->actual_end_state.has_value()) {
      return RunResult::InternalError(
          absl::StrCat(exec_result_proto, " has no actual_end_state"));
    }
    return RunResult(execution_result, *player_result, info.rusage,
                     exec_result_proto.snapshot_id(),
                     static_cast<RunnerPostfailureChecksumStatus>(
                         runner_output_proto.postfailure_checksum_status()));
  }
  return RunResult::InternalError(
      absl::StrCat("Unknown runner exit status ", info.status));
}

absl::StatusOr<RunnerDriver> RunnerDriverFromSnapshot(
    const Snapshot& snapshot, absl::string_view runner_path) {
  std::vector<Snapshot> corpus;
  corpus.push_back(snapshot.Copy());

  MmappedMemoryPtr<char> buffer =
      GenerateRelocatableSnaps(Host::architecture_id, corpus);
  size_t buffer_size = MmappedMemorySize(buffer);

  // memfd_create places limits on the length of the name.
  // The Snapshot ID can be arbitrary. Truncate if needed.
  std::string memfd_name(snapshot.id());
  constexpr size_t kMaxNameLength = 249;
  if (memfd_name.length() > kMaxNameLength) {
    memfd_name.resize(kMaxNameLength);
  }

  // Allocate an anonymous memfile, copy the relocatable buffer contents
  // there, then seal the file to prevent any future writes.
  // TODO(ksteuck): [impl] We can also augment GenerateRelocatableSnaps() API
  // to take a buffer parameter and avoid the extra copy.
  int memfd = memfd_create(memfd_name.c_str(),
                           O_RDWR | MFD_ALLOW_SEALING | MFD_CLOEXEC);
  if (memfd == -1) {
    return absl::ErrnoToStatus(errno, "memfd_create");
  }
  if (ftruncate(memfd, buffer_size) != 0) {
    return absl::ErrnoToStatus(errno, "ftruncate");
  }
  // WARNING: This code uses write(2) to populate the memfd. An appealing
  // alternative is to mmap(2) the FD and do a memcpy. Unfortunately, this
  // approach fails in multithreaded environment if the running process forks.
  CHECK_EQ(Write(memfd, buffer.get(), buffer_size), buffer_size);
  // Once sealed, the file's contents and size cannot be changed.  The seal
  // itself also cannot be modified.
  if (fcntl(memfd, F_ADD_SEALS,
            F_SEAL_SEAL | F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW) != 0) {
    return absl::ErrnoToStatus(errno, "fcntl");
  }

  // This is a tacky way of passing the memfd to the subprocess but on the
  // upside it does not involve passing the actual FD and thus does not
  // need any changes to the runner.
  // man 2 memfd_create lists this as one of the ways to access the shared
  // memory.
  // Possible alternatives to this are:
  //  * /proc/self/fd/$memfd (remove MDF_CLOEXEC above) -- the runner will
  //    access its own FD corresponding to the same in-mem file. This will
  //    leak details of RunnerDriver implementation.
  //  * pass an extra --fd=$memfd to the runner or implement fd:// schema in
  //    the runner. This option requires runner changes and introduces added
  //    complexity around determining the file size.
  std::string corpus_path = absl::StrCat("/proc/", getpid(), "/fd/", memfd);

  // Synthesize a fake corpus name.
  std::string corpus_name = "snapshot_" + snapshot.id();

  return RunnerDriver::ReadingRunner(runner_path, corpus_path, corpus_name,
                                     [memfd] { close(memfd); });
}

}  // namespace silifuzz
