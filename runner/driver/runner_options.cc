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

#include "./runner/driver/runner_options.h"

#include <string>
#include <vector>

#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "./util/checks.h"

namespace silifuzz {
namespace {

// Amount of CPU that snapshot's execution is allowed to spend before
// we consider it a runaway.
// NOTE: there's no true "per-snapshot" timeout in the runner, only per-process
// timeout. In case of *One() family of methods exactly one snapshot gets
// executed so the per-process timeout is more or less the same as per-snapshot.
constexpr inline absl::Duration kPerSnapPlayCpuTimeBudget = absl::Seconds(1);
// Tracing is much slower so allocate more time.
constexpr inline absl::Duration kPerSnapTraceCpuTimeBudget = absl::Seconds(10);

}  // namespace

const RunnerOptions& RunnerOptions::Default() {
  static RunnerOptions* options = new RunnerOptions();
  return *options;
}

RunnerOptions RunnerOptions::PlayOptions(absl::string_view snap_id) {
  return RunnerOptions()
      .set_cpu_time_budget(kPerSnapPlayCpuTimeBudget)
      .set_extra_argv({"--snap_id", std::string(snap_id),
                       // TODO(b/227770288): [bug] Play more than once to ensure
                       // determinism.
                       "--num_iterations", "3"});
}

RunnerOptions RunnerOptions::MakeOptions(absl::string_view snap_id) {
  return RunnerOptions()
      .set_cpu_time_budget(kPerSnapPlayCpuTimeBudget)
      .set_extra_argv({"--snap_id", std::string(snap_id), "--num_iterations",
                       "1", "--make"})
      // Unless VLOG is on discard human-readable failure details
      // (register mismatch, etc) that the _runner_ process will print
      // to stderr. Failures are expected during making.
      .set_map_stderr_to_dev_null(!VLOG_IS_ON(3));
}

RunnerOptions RunnerOptions::VerifyOptions(absl::string_view snap_id) {
  return RunnerOptions()
      .set_cpu_time_budget(kPerSnapPlayCpuTimeBudget)
      .set_extra_argv(
          {"--snap_id", std::string(snap_id), "--num_iterations", "3"})
      .set_disable_aslr(false)
      // Unless VLOG is on, skip runner failure details just like MakeOptions()
      // above.
      .set_map_stderr_to_dev_null(!VLOG_IS_ON(3));
}

RunnerOptions RunnerOptions::TraceOptions(absl::string_view snap_id) {
  return RunnerOptions()
      .set_cpu_time_budget(kPerSnapTraceCpuTimeBudget)
      .set_extra_argv({"--snap_id", std::string(snap_id), "--num_iterations",
                       "1", "--enable_tracer"});
}

RunnerOptions& RunnerOptions::set_extra_argv(
    const std::vector<std::string>& extra_argv) {
  for (const auto& flag : extra_argv) {
    CHECK(!flag.empty());
  }
  this->extra_argv_ = extra_argv;
  return *this;
}

}  // namespace silifuzz
