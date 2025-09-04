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

// SiliFuzz Orchestrator.
// A binary that orchestrates the execution of SiliFuzz runners.
//
// Typical usage:
//   ./silifuzz_orchestrator -max_cpus $(nproc) --runner=<runner path> \
//        --shard_list_file=<file> [-- --runner_flag=value ...]
//
// The runner is required to support the following flags:
//   * --num_iterations=N: run this many snapshots.
//   * --cpu=N: pin itself to the core N.
//
// Orchestrator runs one or more runner binaries, in several threads.
// Runners have a limited time budget, so they are restarted periodically.
// Outputs and exit status from the runners are collected and
// handled.
//
// ASLR is disabled for the runners via personality(ADDR_NO_RANDOMIZE)
// from the Orchestrator.
//
// Assumption:
// runners unconditionally limit the stdout size using RLIMIT_FSIZE.
// This does not affect the stdout size if stdout is a pipe,
// so we redirect stdout to an actual file.
//
// Assumption: Runner closes stdin.

#include <sched.h>
#include <stdint.h>
#include <unistd.h>

#include <algorithm>
#include <csignal>
#include <cstddef>
#include <cstdlib>
#include <filesystem>  // NOLINT
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <thread>  // NOLINT
#include <utility>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/functional/bind_front.h"
#include "absl/log/flags.h"  // IWYU pragma: keep
#include "absl/log/initialize.h"
#include "absl/random/random.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/ascii.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "google/protobuf/message.h"
#include "google/protobuf/text_format.h"
#include "./orchestrator/corpus_util.h"
#include "./orchestrator/orchestrator_util.h"
#include "./orchestrator/result_collector.h"
#include "./orchestrator/silifuzz_orchestrator.h"
#include "./proto/corpus_metadata.pb.h"
#include "./runner/driver/runner_options.h"
#include "./util/checks.h"
#include "./util/cpu_id.h"
#include "./util/span_util.h"
#include "./util/tool_util.h"

ABSL_FLAG(absl::Duration, duration, absl::InfiniteDuration(),
          "Approximate duration.");
ABSL_FLAG(size_t, max_cpus, 0,
          "Number of concurrent jobs (subject to memory budget). When 0 "
          "(default) use as many CPUs as possible.");
ABSL_FLAG(absl::Duration, per_runner_cpu_time_budget, absl::Seconds(10),
          "Per-runner cpu time budget");
ABSL_FLAG(absl::Duration, worker_thread_delay, absl::ZeroDuration(),
          "Delay between starting consecutive worker threads.");
ABSL_FLAG(std::string, runner, "",
          "A reading runner binary. The orchestrator executes this with one of "
          "the corpora randomly.  This must not be empty.");
ABSL_FLAG(std::string, shard_list_file, "",
          "A file containing a list of input corpus shards. This must not be "
          "empty.");
ABSL_FLAG(
    int, binary_log_fd, -1,
    "If non-negative, a writable file descriptor for streaming out a binary "
    "log. The file descriptor should be valid when the orchestrator starts.");
ABSL_FLAG(bool, sequential_mode, false,
          "If true, enumerate snapshots one by one in single-threaded mode and "
          "exit. Ignores --max_cpus.");
ABSL_FLAG(std::string, corpus_metadata_file, "",
          "A file containing description of the corpus formatted as "
          "silifuzz.proto.CorpusMetadata text proto");
ABSL_FLAG(double, log_session_summary_probability, 0,
          "A probability (between 0 and 1) indicating a chance of this "
          "execution to log full summary at the end (only when "
          "--binary_log_fd is set)");
ABSL_FLAG(std::string, orchestrator_version, "",
          "Version of this binary to be used for logging.");
ABSL_FLAG(absl::Duration, watchdog_allowed_overrun, absl::ZeroDuration(),
          "When > 0, a watchdog thread will terminate this process after "
          "exceeding duration+overrun");
ABSL_FLAG(int64_t, num_iterations, 5000000, "Number of iterations per runner.");
ABSL_FLAG(
    std::string, limit_memory_usage_mb, "unlimited",
    "How much memory (in Mb) can the scanning process use. The default is "
    "unlimited. When set, the orchestrator will _try to_ limit the memory "
    "usage of itself + all the runner processes by loading just a random "
    "fraction of the shards. A special value `auto` can be used to "
    "automatically determine the amount of free memory from /proc/meminfo");
// TODO(b/233457080): [bug] Investigate the cause of EXECUTION_RUNAWAY errors.
ABSL_FLAG(bool, report_runaways_as_errors, false,
          "Whether runaway snapshot should be reported as errors");
ABSL_FLAG(int, fail_after_n_errors, std::numeric_limits<int>::max(),
          "Fail soon after detecting this many errors.");

namespace silifuzz {

namespace {

// Lists all available CPUs according to sched_getaffinity(2).
std::vector<int> AvailableCpus() {
  std::vector<int> available_cpus;
  ForEachAvailableCPU([&](int cpu) { available_cpus.push_back(cpu); });
  CHECK(!available_cpus.empty());
  return available_cpus;
}

// Initializes the orchestrator environment.
CpuExecutionContext* OrchestratorInit(
    absl::Time deadline, int num_threads,
    const CpuExecutionContext::ResultCallback& result_cb) {
  static CpuExecutionContext ctx(deadline, num_threads, result_cb);

  struct sigaction sigact = {};
  sigact.sa_handler = [](int) {
    ABSL_RAW_LOG(INFO, "SIGINT/SIGALRM caught; shutting down worker threads\n");
    ctx.Stop();
  };
  sigaction(SIGINT, &sigact, nullptr);
  sigaction(SIGALRM, &sigact, nullptr);

  if (auto overrun = absl::GetFlag(FLAGS_watchdog_allowed_overrun);
      overrun > absl::ZeroDuration()) {
    absl::Duration watchdog_timeout = deadline - absl::Now() + overrun;
    std::thread watchdog([watchdog_timeout]() {
      absl::SleepFor(watchdog_timeout);
      ABSL_RAW_LOG(ERROR, "Terminated by watchdog\n");
      _exit(EXIT_SUCCESS);
    });
    watchdog.detach();
  }

  return &ctx;
}

absl::Status ReadProtoFromTextFile(absl::string_view filename,
                                   ::google::protobuf::Message* proto) {
  ASSIGN_OR_RETURN_IF_NOT_OK(auto data, GetFileContents(filename));
  if (!google::protobuf::TextFormat::ParseFromString(data, proto)) {
    return absl::InternalError(absl::StrCat("Failed to parse ", filename,
                                            " into ", proto->GetTypeName()));
  }
  return absl::OkStatus();
}

struct RuntimeMetadata {
  proto::CorpusMetadata corpus_metadata;
  std::string orchestrator_version;
};

absl::StatusOr<RuntimeMetadata> LoadRuntimeMetadata() {
  std::string corpus_metadata_file = absl::GetFlag(FLAGS_corpus_metadata_file);
  proto::CorpusMetadata metadata;
  RETURN_IF_NOT_OK_PLUS(
      ReadProtoFromTextFile(corpus_metadata_file, &metadata),
      "Corpus metadata file not found. Did you set --corpus_metadata_file: ");
  std::string version = absl::GetFlag(FLAGS_orchestrator_version);
  return RuntimeMetadata{metadata, version};
}

bool SessionLoggingEnabled() {
  static bool enabled =
      absl::Uniform(absl::BitGen{}, 0, 1.0) <=
          absl::GetFlag(FLAGS_log_session_summary_probability) &&
      absl::GetFlag(FLAGS_binary_log_fd) >= 0;
  return enabled;
}

int OrchestratorMain(const OrchestratorResources& resources,
                     const std::string& runner,
                     const std::vector<std::string>& runner_extra_argv) {
  LOG_INFO("SiliFuzz Orchestrator started");

  const absl::Time start_time = absl::Now();
  absl::Time deadline = start_time + absl::GetFlag(FLAGS_duration);

  const absl::StatusOr<RuntimeMetadata> runtime_meta = LoadRuntimeMetadata();
  if (!runtime_meta.ok()) {
    LOG_ERROR(runtime_meta.status().message());
    return EXIT_FAILURE;
  }

  // Load corpora and exit if there is any error.
  // File descriptors of the uncompressed corpora are kept open
  // until this struct goes out of scope.
  const absl::StatusOr<InMemoryCorpora> in_memory_corpora =
      LoadCorpora(resources.shards);
  if (!in_memory_corpora.ok()) {
    LOG_ERROR("Cannot load corpora: ", in_memory_corpora.status().message());
    return EXIT_FAILURE;
  }

  absl::Status validation_status = ValidateCorpus(*in_memory_corpora);
  if (!validation_status.ok()) {
    LOG_ERROR(validation_status.message());
    return EXIT_FAILURE;
  }

  const absl::Duration runner_cpu_time_budget =
      absl::GetFlag(FLAGS_per_runner_cpu_time_budget);
  bool sequential_mode = absl::GetFlag(FLAGS_sequential_mode);
  // Note that num_concurrent_runners should already be capped to the number of
  // CPUs available.
  uint64_t num_threads = resources.num_concurrent_runners;
  if (sequential_mode) {
    LOG_INFO("Running in sequential mode");
    num_threads = 1;
  }
  std::vector<RunnerThreadArgs> thread_args;
  std::vector<int> cpus = AvailableCpus();
  // Introduces the randomness in the order of CPUs to be scanned. This is to
  // avoid the case where silifuzz only scans CPUs with lower IDs on machines
  // with many cores and limited memory.
  std::shuffle(cpus.begin(), cpus.end(), absl::BitGen());
  auto cpus_per_thread = PartitionEvenly(cpus, num_threads);
  for (int thread_idx = 0; thread_idx < num_threads; ++thread_idx) {
    RunnerOptions runner_options = RunnerOptions::Default();
    runner_options.set_cpu_time_budget(runner_cpu_time_budget)
        .set_sequential_mode(sequential_mode)
        .set_extra_argv(runner_extra_argv);
    absl::Span<int> target_cpus = cpus_per_thread[thread_idx];
    CHECK_GT(target_cpus.size(), 0);
    VLOG_INFO(0, target_cpus.size(), " CPUs are assigned to T", thread_idx);
    thread_args.push_back(
        {.thread_idx = thread_idx,
         .runner = runner,
         .corpora = &*in_memory_corpora,
         .cpus = std::vector<int>(target_cpus.begin(), target_cpus.end()),
         .runner_options = runner_options});
  }

  ResultCollector result_collector(
      absl::GetFlag(FLAGS_binary_log_fd), start_time,
      {.report_runaways_as_errors =
           absl::GetFlag(FLAGS_report_runaways_as_errors),
       .fail_after_n_errors = absl::GetFlag(FLAGS_fail_after_n_errors)});

  if (SessionLoggingEnabled()) {
    if (absl::Status s = result_collector.LogSessionStart(
            runtime_meta->corpus_metadata, runtime_meta->orchestrator_version);
        !s.ok()) {
      LOG_ERROR("Binary logging failed: ", s.message());
      return EXIT_FAILURE;
    }
  }

  CpuExecutionContext* ctx = OrchestratorInit(
      deadline, num_threads,
      absl::bind_front(&ResultCollector::operator(), &result_collector));

  absl::Duration staggering_delay = absl::GetFlag(FLAGS_worker_thread_delay);
  // Create worker threads.
  std::vector<std::thread> threads;
  threads.reserve(num_threads);
  for (const RunnerThreadArgs& args : thread_args) {
    if (ctx->ShouldStop()) {
      break;
    }
    threads.emplace_back(RunnerThread, ctx, args);
    absl::SleepFor(staggering_delay);
  }

  ctx->EventLoop();

  // Join worker threads.
  for (size_t thread_idx = 0; thread_idx < threads.size(); ++thread_idx) {
    if (threads[thread_idx].joinable()) {
      VLOG_INFO(0, "Joining ", thread_idx);
      threads[thread_idx].join();
    }
  }
  ctx->ProcessResultQueue();
  result_collector.LogSummary(true);
  Summary summary = result_collector.summary();
  if (SessionLoggingEnabled() || summary.num_failed_snapshots > 0) {
    if (absl::Status s = result_collector.LogSessionSummary(
            runtime_meta->corpus_metadata, runtime_meta->orchestrator_version);
        !s.ok()) {
      LOG_ERROR(s.message());
    }
  }
  if (summary.num_failed_snapshots > 0) {
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

std::vector<std::string> LoadShardFilenames(
    const std::filesystem::path& shard_list_file) {
  std::ifstream ifs;
  ifs.open(shard_list_file);
  VLOG_INFO(0, "Loading shards from ", shard_list_file.c_str());
  if (!ifs.good()) {
    LOG_ERROR("Error opening ", shard_list_file.c_str());
    return {};
  }
  std::vector<std::string> shards;
  std::string line;
  while (std::getline(ifs, line)) {
    absl::StripAsciiWhitespace(&line);
    if (!line.empty() && line[0] != '#') {
      shards.emplace_back(std::move(line));
    }
  }
  if (ifs.bad()) {
    LOG_ERROR("Error reading ", shard_list_file.c_str());
    return {};
  }
  ifs.close();
  return shards;
}

}  // namespace
}  // namespace silifuzz

int main(int argc, char** argv) {
  std::vector<char*> remaining_args = absl::ParseCommandLine(argc, argv);
  absl::InitializeLog();
  std::string runner = absl::GetFlag(FLAGS_runner);
  if (runner.empty()) {
    std::cerr << "--runner must be set" << '\n';
    return EXIT_FAILURE;
  }
  silifuzz::OrchestratorResources resources;
  // Load the corpus shard list.
  std::string shard_list_file = absl::GetFlag(FLAGS_shard_list_file);
  if (shard_list_file.empty()) {
    std::cerr << "--shard_list_file must be set" << '\n';
    return EXIT_FAILURE;
  }
  resources.shards = silifuzz::LoadShardFilenames(shard_list_file);
  if (resources.shards.empty()) {
    std::cerr
        << "At least one corpus file must be listed in the shard_file_list"
        << '\n';
    return EXIT_FAILURE;
  }
  const int total_shards = resources.shards.size();

  uint64_t max_cpus = absl::GetFlag(FLAGS_max_cpus);
  if (max_cpus == 0) {
    max_cpus = silifuzz::AvailableCpus().size();
  }
  resources.num_concurrent_runners =
      std::min<uint64_t>(silifuzz::AvailableCpus().size(), max_cpus);

  std::string limit_memory_usage_mb =
      absl::GetFlag(FLAGS_limit_memory_usage_mb);
  if (limit_memory_usage_mb != "unlimited") {
    int64_t limit_memory_usage_mb_as_int = 0;
    if (limit_memory_usage_mb == "auto") {
      if (auto v = silifuzz::AvailableMemoryMb(); !v.ok()) {
        LOG_ERROR("Failed to get available memory: ", v.status().message());
        return EXIT_FAILURE;
      } else {
        // Apply 0.8 fudge factor such that we don't consume all the available
        // memory.
        limit_memory_usage_mb_as_int = *v * 0.8;
      }
    } else if (!absl::SimpleAtoi(limit_memory_usage_mb,
                                 &limit_memory_usage_mb_as_int)) {
      LOG_ERROR("Failed to parse: ", limit_memory_usage_mb);
      return EXIT_FAILURE;
    }
    absl::Status cap_resources_status = silifuzz::CapResourcesToMemLimit(
        limit_memory_usage_mb_as_int, resources);
    if (!cap_resources_status.ok()) {
      LOG_ERROR(cap_resources_status.message());
      return EXIT_FAILURE;
    }
  }

  std::vector<std::string> runner_extra_argv;
  runner_extra_argv.push_back(
      absl::StrCat("--num_iterations=", absl::GetFlag(FLAGS_num_iterations)));
  // Collect runner arguments.
  for (size_t i = 1; i < remaining_args.size(); ++i) {
    runner_extra_argv.push_back(remaining_args[i]);
  }

  LOG_INFO("AVAIL MEM: ", silifuzz::AvailableMemoryMb().value_or(0),
           " LOADABLE SHARDS: ", resources.shards.size(),
           " TOTAL SHARDS: ", total_shards,
           " CPUS: ", silifuzz::AvailableCpus().size());

  return silifuzz::OrchestratorMain(resources, runner, runner_extra_argv);
}
