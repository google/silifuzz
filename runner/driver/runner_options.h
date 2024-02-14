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

#ifndef THIRD_PARTY_SILIFUZZ_RUNNER_DRIVER_RUNNER_OPTIONS_H_
#define THIRD_PARTY_SILIFUZZ_RUNNER_DRIVER_RUNNER_OPTIONS_H_

#include <cstddef>
#include <string>
#include <vector>

#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "./util/cpu_id.h"

namespace silifuzz {

class RunnerDriver;  // fwd declaration for friendship below.

// Options controlling the invocation of a runner binary. These correspond to
// FLAGS_* declared in runner_flags.h.
//
// This class is thread-compatible.
class RunnerOptions {
 public:
  // Returns the default RunnerOptions value. See default field values below for
  // details.
  static const RunnerOptions& Default();

  // API for setting and reading various bits of the RunnerOptions class.
  RunnerOptions& set_cpu(int cpu) {
    this->cpu_ = cpu;
    return *this;
  }
  RunnerOptions& set_cpu_time_budget(absl::Duration cpu_time_budget) {
    this->cpu_time_budget_ = cpu_time_budget;
    return *this;
  }
  RunnerOptions& set_wall_time_budget(absl::Duration wall_time_budget) {
    this->wall_time_budget_ = wall_time_budget;
    return *this;
  }
  RunnerOptions& set_extra_argv(const std::vector<std::string>& extra_argv);
  RunnerOptions& set_disable_aslr(bool disable_aslr) {
    this->disable_aslr_ = disable_aslr;
    return *this;
  }
  RunnerOptions& set_sequential_mode(bool sequential_mode) {
    this->sequential_mode_ = sequential_mode;
    return *this;
  }

  RunnerOptions& set_map_stderr_to_dev_null(bool map_stderr_to_dev_null) {
    this->map_stderr_to_dev_null_ = map_stderr_to_dev_null;
    return *this;
  }

  int cpu() const { return cpu_; }
  absl::Duration cpu_time_budget() const { return cpu_time_budget_; }
  absl::Duration wall_time_budget() const { return wall_time_budget_; }
  // extra_argv() is notoriously absent to prevent leaking some internal
  // implementation details.
  bool disable_aslr() const { return disable_aslr_; }
  bool sequential_mode() const { return sequential_mode_; }
  bool map_stderr_to_dev_null() const { return map_stderr_to_dev_null_; }

  RunnerOptions(const RunnerOptions&) = default;
  RunnerOptions(RunnerOptions&&) = default;
  RunnerOptions& operator=(const RunnerOptions&) = default;
  RunnerOptions& operator=(RunnerOptions&&) = default;

  // Returns a default instance of RunnerOptions suitable for Playing/Making/etc
  // for `snap_id`.
  static RunnerOptions PlayOptions(absl::string_view snap_id,
                                   int cpu = kAnyCPUId);
  // If 'max_pages_to_add' is not 0, the runner adds up to that many pages
  // during making.
  static RunnerOptions MakeOptions(absl::string_view snap_id,
                                   size_t max_pages_to_add = 0,
                                   int cpu = kAnyCPUId);
  static RunnerOptions VerifyOptions(absl::string_view snap_id,
                                     int cpu = kAnyCPUId);
  static RunnerOptions TraceOptions(absl::string_view snap_id,
                                    size_t num_iterations = 1,
                                    int cpu = kAnyCPUId);

 private:
  friend class RunnerDriver;

  RunnerOptions() = default;

  const std::vector<std::string>& extra_argv() const { return extra_argv_; }

  // CPU to pin to.
  int cpu_ = kAnyCPUId;

  // How much CPU time each runner invocation gets.
  // TODO(ksteuck): [as-needed] the underlying setrlimit(2) call provides
  // whole-second precision. We can utilize setitimer if sub-second limit is
  // needed.
  absl::Duration cpu_time_budget_ = absl::InfiniteDuration();

  // How much wall time each runner invocation gets.
  absl::Duration wall_time_budget_ = absl::InfiniteDuration();

  // Any additional parameters passed to each runner binary.
  std::vector<std::string> extra_argv_ = {};

  // If ASLR should be disabled.
  bool disable_aslr_ = true;

  // If true, enumerate all corpora sequentially and then exit.
  bool sequential_mode_ = false;

  // If true, map runner's stderr to /dev/null.
  bool map_stderr_to_dev_null_ = false;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_RUNNER_DRIVER_RUNNER_OPTIONS_H_
