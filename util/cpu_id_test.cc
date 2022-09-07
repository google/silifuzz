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

#include "./util/cpu_id.h"

#include <sched.h>

#include "gtest/gtest.h"
#include "./util/checks.h"
#include "./util/itoa.h"

namespace silifuzz {
namespace {

TEST(CPUId, BasicTest) {
  cpu_set_t all_cpus;
  ASSERT_EQ(sched_getaffinity(0, sizeof(all_cpus), &all_cpus), 0);

  int num_trials = 0;
  int passes = 0;
  for (int i = 0; i < CPU_SETSIZE; i++) {
    if (CPU_ISSET(i, &all_cpus)) {
      if (SetCPUId(i) != 0) {
        LOG_ERROR("Cannot bind to CPU ", IntStr(i));
        continue;
      }

      // There is no guarantee that a thread stays on a core so this can fail.
      const int cpu_before = sched_getcpu();
      const int getcpu_result = GetCPUId();
      const int cpu_after = sched_getcpu();

      // Discard trial if thread obviously has migrated.
      if (cpu_before == cpu_after) {
        num_trials++;
        if (getcpu_result == cpu_before) {
          passes++;
        }
      }
    }
  }

  // This is chosen empirically to keep failure rate below 1 in 10000.
  constexpr double kAcceptableErrorRate = 0.10;
  EXPECT_GT(passes, num_trials * (1.0 - kAcceptableErrorRate));
}

}  // namespace
}  // namespace silifuzz
