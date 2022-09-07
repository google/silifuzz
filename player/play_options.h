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

#ifndef THIRD_PARTY_SILIFUZZ_PLAYER_PLAY_OPTIONS_H_
#define THIRD_PARTY_SILIFUZZ_PLAYER_PLAY_OPTIONS_H_

#include <stdint.h>

#include "absl/time/time.h"
#include "./util/cpu_id.h"

namespace silifuzz {

// Common options for playing a snapshot.
//
// Currently consists of just the run_time_budget.
//
// This class is a thread-compatible value type.
class PlayOptions {
 public:
  // Initializes to Default().
  constexpr PlayOptions() {}
  ~PlayOptions() = default;

  // Default values.
  static const PlayOptions& Default();

  // Usage requires this.
  bool IsValid() const;

  // Intentionally movable and copyable.

  // Amount of CPU that snapshot's execution is allowed to spend before
  // we consiter it a runaway.
  absl::Duration run_time_budget = absl::Seconds(3);

  // A Player::CPUUsageBaseline() value that we will apply when estimating
  // how much CPU snapshot execution took.
  //
  // The default is the lowest known value for Player::CPUUsageBaseline()
  // among the platforms we run on.
  absl::Duration cpu_usage_baseline = absl::Nanoseconds(1600);

  // Return cpu usage nsec value (ExecuteCommandResult::cpu_usage_nsec)
  // corrected by cpu_usage_baseline.
  // Can be negative if cpu_usage_baseline is over-estimated.
  absl::Duration CorrectedCpuUsage(int64_t cpu_usage_nsec) const;

  // ID of the preferred CPU to run snapshot, or kAnyCPUId if no preference.
  int preferred_cpu_id = kAnyCPUId;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_PLAYER_PLAY_OPTIONS_H_
