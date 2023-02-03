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

#include "./orchestrator/result_collector.h"

#include <sched.h>
#include <stdint.h>
#include <sys/resource.h>

#include <algorithm>
#include <cerrno>
#include <memory>
#include <string>
#include <vector>

#include "google/protobuf/duration.pb.h"
#include "google/protobuf/timestamp.pb.h"
#include "absl/flags/flag.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "./common/snapshot_enums.h"
#include "./orchestrator/binary_log_channel.h"
#include "./orchestrator/orchestrator_util.h"
#include "./player/player_result_proto.h"
#include "./proto/binary_log_entry.pb.h"
#include "./proto/corpus_metadata.pb.h"
#include "./proto/session_summary.pb.h"
#include "./proto/snapshot_execution_result.pb.h"
#include "./runner/driver/runner_driver.h"
#include "./util/checks.h"
#include "./util/hostname.h"
#include "./util/itoa.h"

ABSL_FLAG(bool, enable_v1_compat_logging, false, "Enable V1-style logging");
// TODO(b/233457080): [bug] Investigate the cause of EXECUTION_RUNAWAY errors.
ABSL_FLAG(bool, report_runaways_as_errors, false,
          "Whether runaway snapshot should be reported as errors");

namespace silifuzz {
namespace {

google::protobuf::Timestamp TimeToProto(absl::Time t) {
  const int64_t s = absl::ToUnixSeconds(t);
  google::protobuf::Timestamp timestamp;
  timestamp.set_seconds(s);
  timestamp.set_nanos((t - absl::FromUnixSeconds(s)) / absl::Nanoseconds(1));
  return timestamp;
}

google::protobuf::Duration DurationToProto(absl::Duration d) {
  google::protobuf::Duration proto;
  // s and n may both be negative, per the Duration proto spec.
  const int64_t s = absl::IDivDuration(d, absl::Seconds(1), &d);
  const int64_t n = absl::IDivDuration(d, absl::Nanoseconds(1), &d);
  proto.set_seconds(s);
  proto.set_nanos(n);
  return proto;
}

absl::Status GetRUsage(absl::Duration *user_time, absl::Duration *sys_time) {
  struct rusage rusage = {};
  if (getrusage(RUSAGE_CHILDREN, &rusage) == -1) {
    return absl::ErrnoToStatus(errno, "getrusage()");
  }
  *user_time =
      absl::Trunc(absl::DurationFromTimeval(rusage.ru_utime), absl::Seconds(1));
  *sys_time =
      absl::Trunc(absl::DurationFromTimeval(rusage.ru_stime), absl::Seconds(1));
  return absl::OkStatus();
}

// Converts RunResult into a BinaryLogEntry.
// Assumes the result was produced on the running host.
absl::StatusOr<proto::BinaryLogEntry> RunResultToSnapshotExecutionResult(
    const RunnerDriver::RunResult &run_result, absl::Time now,
    const std::string &session_id) {
  DCHECK(!run_result.success());
  proto::BinaryLogEntry entry;
  proto::SnapshotExecutionResult *snapshot_execution_result =
      entry.mutable_snapshot_execution_result();
  snapshot_execution_result->set_snapshot_id(run_result.snapshot_id());
  RETURN_IF_NOT_OK(PlayerResultProto::ToProto(
      run_result.player_result(),
      *snapshot_execution_result->mutable_player_result()));

  *snapshot_execution_result->mutable_time() = TimeToProto(now);
  snapshot_execution_result->set_hostname(std::string(ShortHostname()));

  *entry.mutable_timestamp() = TimeToProto(now);
  entry.set_session_id(session_id);
  return entry;
}

// Returns the number of CPUs available according to sched_getaffinity.
int NumCpus() {
  cpu_set_t all_cpus;
  CPU_ZERO(&all_cpus);
  int num_cpus = 0;
  bool success = sched_getaffinity(0, sizeof(all_cpus), &all_cpus) == 0;
  if (!success) {
    LOG_FATAL("Cannot get current CPU affinity mask: ", ErrnoStr(errno));
  }
  for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
    if (CPU_ISSET(cpu, &all_cpus)) {
      num_cpus++;
    }
  }
  return num_cpus;
}

// ===========================================================================
// V1 checker-compatible logging methods.
// The behavior of all methods is controlled by a single
// --enable_v1_compat_logging flag. When the flag is reset no output is
// produced.

// Logs the supplied run_result in V1 format e.g.
// "Silifuzz detected issue on CPU ..."
void LogV1SingleSnapFailure(const RunnerDriver::RunResult &run_result) {
  DCHECK(!run_result.success());
  static bool enable_v1_compat_logging =
      absl::GetFlag(FLAGS_enable_v1_compat_logging);
  if (!enable_v1_compat_logging) return;
  std::cerr << "Silifuzz detected issue on CPU "
            << run_result.player_result().cpu_id << " running snapshot "
            << run_result.snapshot_id() << std::endl;
}

// Logs V1-style summary e.g.
// Silifuzz Checker Result:{issues_detected ... }
void LogV1CompatSummary(const Summary &summary, absl::Duration elapsed,
                        uint64_t max_rss_kb) {
  static bool enable_v1_compat_logging =
      absl::GetFlag(FLAGS_enable_v1_compat_logging);
  if (!enable_v1_compat_logging) return;
  absl::Duration user_time = absl::ZeroDuration(),
                 sys_time = absl::ZeroDuration();
  if (absl::Status s = GetRUsage(&user_time, &sys_time); !s.ok()) {
    LOG_ERROR(s.message());
    return;
  }

  // The ? fields are irrelevant/not consumed by anyone.
  std::cerr << "Silifuzz Checker Result:{"
            << "issues_detected = " << summary.num_failed_snapshots
            << ", num_cores = " << NumCpus() << ", elapsed_time = " << elapsed
            << ", user_time = " << absl::FormatDuration(user_time)
            << ", system_time = " << absl::FormatDuration(sys_time)
            << ", batch_count = ?, play_count = " << summary.play_count
            << ", snapshot_execution_errors = 0"
            << ", runaway_count = " << summary.num_runaway_snapshots
            << ", max_rss_kb = " << max_rss_kb
            << ", had_checker_misconfigurations = false}" << std::endl;
}

}  // namespace

ResultCollector::ResultCollector(int binary_log_channel_fd,
                                 absl::Time start_time)
    : binary_log_producer_(nullptr), start_time_(start_time) {
  binary_log_producer_ =
      binary_log_channel_fd >= 0
          ? std::make_unique<BinaryLogProducer>(binary_log_channel_fd)
          : nullptr;
  session_id_ =
      absl::StrCat(ShortHostname(), "/", absl::ToUnixNanos(start_time_));
}

// Processes a single execution result.
void ResultCollector::operator()(const RunnerDriver::RunResult &result) {
  static bool report_runaways_as_errors =
      absl::GetFlag(FLAGS_report_runaways_as_errors);

  ++summary_.play_count;
  max_rss_kb_ = std::max(max_rss_kb_, MaxRunnerRssSizeBytes(getpid()) / 1024);
  if (!result.success()) {
    if (result.player_result().outcome ==
        snapshot_types::PlaybackOutcome::kExecutionRunaway) {
      summary_.num_runaway_snapshots++;
      if (!report_runaways_as_errors) return;
    }
    ++summary_.num_failed_snapshots;
    LogV1SingleSnapFailure(result);
    absl::StatusOr<proto::BinaryLogEntry> entry_or =
        RunResultToSnapshotExecutionResult(result, absl::Now(), session_id_);
    if (entry_or.ok()) {
      if (binary_log_producer_) {
        if (absl::Status s = binary_log_producer_->Send(*entry_or); !s.ok()) {
          LOG_ERROR(s.message());
        }
      }
    } else {
      LOG_ERROR(entry_or.status().message());
    }
  }
  LogSummary();
}

void ResultCollector::LogSummary(bool always) {
  absl::Time now = absl::Now();
  if (always || now > last_summary_log_time_ + log_interval_) {
    LogV1CompatSummary(summary_,
                       absl::Trunc(now - start_time_, absl::Seconds(1)),
                       max_rss_kb_);
    last_summary_log_time_ = now;
    log_interval_ = std::min(log_interval_ * 2, absl::Minutes(1));
  }
}

absl::Status ResultCollector::LogSessionSummary(
    const proto::CorpusMetadata &corpus_metadata,
    absl::string_view orchestrator_version) {
  if (binary_log_producer_ == nullptr) {
    return absl::OkStatus();
  }
  absl::Time now = absl::Now();
  proto::BinaryLogEntry entry;
  entry.set_session_id(session_id_);
  *entry.mutable_timestamp() = TimeToProto(now);
  absl::Duration user_time = absl::ZeroDuration();
  absl::Duration sys_time = absl::ZeroDuration();
  RETURN_IF_NOT_OK(GetRUsage(&user_time, &sys_time));
  auto ru = entry.mutable_session_summary()->mutable_resource_usage();
  *ru->mutable_user_time() = DurationToProto(user_time);
  *ru->mutable_system_time() = DurationToProto(sys_time);
  ru->set_max_rss_kb(max_rss_kb_);

  auto playback_summary =
      entry.mutable_session_summary()->mutable_playback_summary();
  playback_summary->set_num_failed_snapshots(summary_.num_failed_snapshots);
  playback_summary->set_play_count(summary_.play_count);
  playback_summary->set_num_runaway_snapshots(summary_.num_runaway_snapshots);

  *entry.mutable_session_summary()->mutable_duration() =
      DurationToProto(now - start_time_);
  if (!orchestrator_version.empty()) {
    entry.mutable_session_summary()->mutable_orchestrator_info()->set_version(
        std::string(orchestrator_version));
  }

  entry.mutable_session_summary()->mutable_machine_info()->set_num_cores(
      NumCpus());
  entry.mutable_session_summary()->mutable_machine_info()->set_hostname(
      std::string(ShortHostname()));

  *entry.mutable_session_summary()->mutable_corpus_metadata() = corpus_metadata;

  return binary_log_producer_->Send(entry);
}

}  // namespace silifuzz
