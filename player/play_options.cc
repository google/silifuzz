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

#include "./player/play_options.h"

#include <sched.h>  // CPU_SETSIZE
#include <stdint.h>

#include "absl/time/time.h"
#include "./util/cpu_id.h"

namespace silifuzz {

// static
const PlayOptions& PlayOptions::Default() {
  static constexpr PlayOptions x = PlayOptions();
  return x;
}

bool PlayOptions::IsValid() const {
  return run_time_budget >= absl::ZeroDuration() &&
         cpu_usage_baseline >= absl::ZeroDuration() &&
         // The upperbound should be number of CPUs but there is
         // no simple way to get this without libc.
         (preferred_cpu_id == kAnyCPUId ||
          (preferred_cpu_id >= 0 && preferred_cpu_id < CPU_SETSIZE));
}

absl::Duration PlayOptions::CorrectedCpuUsage(int64_t cpu_usage_nsec) const {
  // We correct a failed measurement to be the baseline: We assume that a
  // snapshot for which cpu_usage measurement failed was equivalent to an
  // empty snapshot. Ideally we should instead use a recent average of
  // CorrectedCpuUsage() values.
  return cpu_usage_nsec == 0
             ? absl::ZeroDuration()
             : absl::Nanoseconds(cpu_usage_nsec) - cpu_usage_baseline;
}

}  // namespace silifuzz
