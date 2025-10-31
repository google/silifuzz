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

#include <cstddef>
#include <string>
#include <vector>

#include "absl/log/log.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "./player/play_options.h"
#include "./util/checks.h"

namespace silifuzz {
namespace {

// Tracing is much slower so allocate more time.
constexpr inline absl::Duration kPerSnapTraceCpuTimeBudget = absl::Seconds(10);

}  // namespace

const RunnerOptions& RunnerOptions::Default() {
  static RunnerOptions* options = new RunnerOptions();
  return *options;
}

RunnerOptions RunnerOptions::PlayOptions(absl::string_view snap_id, int cpu) {
  return RunnerOptions()
      .set_cpu_time_budget(PlayOptions::Default().run_time_budget)
      .set_cpu(cpu)
      .set_extra_argv(
          {"--snap_id", std::string(snap_id),
           // Play more than once to ensure determinism.
           //
           // We previously observed snapshots that pass the first iteration but
           // fail subsequently. For example, one such snapshot has a
           // non-deterministic ES (segment register) end state. The x86 `iret`
           // instruction has a particular arcane detail: it may clear the
           // segment selector value on return to user, causing any segment
           // register read to return an invalid value. This happens
           // occasionally if an interrupt (e.g. minor page fault) happens
           // during execution.
           "--num_iterations", "3"});
}

RunnerOptions RunnerOptions::MakeOptions(absl::string_view snap_id,
                                         size_t max_pages_to_add, int cpu,
                                         absl::Duration cpu_time_budget) {
  std::vector<std::string> extra_argv = {"--snap_id", std::string(snap_id),
                                         "--num_iterations", "1", "--make"};

  // For compatibility with old runner binaries, hide this option if
  // max_pages_to_add is 0.
  if (max_pages_to_add > 0) {
    extra_argv.push_back("--max_pages_to_add");
    extra_argv.push_back(absl::StrCat(max_pages_to_add));
  }

  return RunnerOptions()
      .set_cpu_time_budget(cpu_time_budget)
      .set_cpu(cpu)
      .set_extra_argv(extra_argv)
      // Unless VLOG is on discard human-readable failure details
      // (register mismatch, etc) that the _runner_ process will print
      // to stderr. Failures are expected during making.
      .set_map_stderr_to_dev_null(!VLOG_IS_ON(3));
}

RunnerOptions RunnerOptions::VerifyOptions(absl::string_view snap_id, int cpu,
                                           absl::Duration cpu_time_budget) {
  return RunnerOptions()
      .set_cpu_time_budget(cpu_time_budget)
      .set_cpu(cpu)
      .set_extra_argv(
          {"--snap_id", std::string(snap_id), "--num_iterations", "3"})
      .set_disable_aslr(false)
      // Unless VLOG is on, skip runner failure details just like MakeOptions()
      // above.
      .set_map_stderr_to_dev_null(!VLOG_IS_ON(3));
}

RunnerOptions RunnerOptions::TraceOptions(absl::string_view snap_id,
                                          size_t num_iterations, int cpu) {
  return RunnerOptions()
      .set_cpu_time_budget(kPerSnapTraceCpuTimeBudget)
      .set_cpu(cpu)
      .set_extra_argv({"--snap_id", std::string(snap_id), "--num_iterations",
                       absl::StrCat(num_iterations), "--enable_tracer"});
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
