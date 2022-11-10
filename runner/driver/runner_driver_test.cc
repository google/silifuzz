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

#include <sys/types.h>
#include <sys/user.h>

#include <filesystem>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "./common/snapshot_enums.h"
#include "./runner/runner_provider.h"
#include "./snap/testing/snap_test_snaps.h"
#include "./snap/testing/snap_test_types.h"
#include "./util/path_util.h"
#include "./util/testing/status_macros.h"
#include "./util/testing/status_matchers.h"

namespace silifuzz {
namespace {
using silifuzz::testing::StatusIs;
using snapshot_types::PlaybackOutcome;
using ::testing::HasSubstr;

RunnerDriver HelperDriver() {
  return RunnerDriver::BakedRunner(RunnerTestHelperLocation());
}

TEST(RunnerDriver, BasicRun) {
  RunnerDriver driver = HelperDriver();
  Snap endAsExpectedSnap =
      GetSnapRunnerTestSnap(SnapRunnerTestType::kEndsAsExpected);
  auto run_result_or = driver.PlayOne(endAsExpectedSnap.id);
  ASSERT_OK(run_result_or);
  ASSERT_TRUE(run_result_or->success());

  Snap syscallSnap = GetSnapRunnerTestSnap(SnapRunnerTestType::kSyscall);
  run_result_or = driver.PlayOne(syscallSnap.id);
  ASSERT_THAT(run_result_or,
              StatusIs(absl::StatusCode::kInternal, HasSubstr("syscall")));
}

TEST(RunnerDriver, BasicMake) {
  RunnerDriver driver = HelperDriver();
  Snap sigSegvReadSnap =
      GetSnapRunnerTestSnap(SnapRunnerTestType::kSigSegvRead);
  auto make_result_or = driver.MakeOne(sigSegvReadSnap.id);
  ASSERT_OK(make_result_or);
  ASSERT_FALSE(make_result_or->success());
  ASSERT_EQ(make_result_or->player_result().outcome,
            PlaybackOutcome::kExecutionMisbehave);
  ASSERT_EQ(make_result_or->snapshot_id(), sigSegvReadSnap.id);
}

TEST(RunnerDriver, BasicTrace) {
  RunnerDriver driver = HelperDriver();
  Snap endAsExpectedSnap =
      GetSnapRunnerTestSnap(SnapRunnerTestType::kEndsAsExpected);
  bool hit_initial_snap_rip = false;
  auto cb = [&hit_initial_snap_rip, &endAsExpectedSnap](
                pid_t pid, const user_regs_struct& regs,
                HarnessTracer::CallbackReason reason) {
    if (regs.rip == endAsExpectedSnap.registers->gregs.rip) {
      hit_initial_snap_rip = true;
      return HarnessTracer::kStopTracing;
    }
    return HarnessTracer::kKeepTracing;
  };
  auto trace_result_or = driver.TraceOne(endAsExpectedSnap.id, cb);
  ASSERT_OK(trace_result_or);
  ASSERT_TRUE(trace_result_or->success());
  ASSERT_TRUE(hit_initial_snap_rip);
}

TEST(RunnerDriver, Cleanup) {
  auto tmp_binary = CreateTempFile("binary");
  ASSERT_OK(tmp_binary);
  ASSERT_TRUE(std::filesystem::exists(*tmp_binary));
  bool file_removed = false;
  {
    RunnerDriver driver = RunnerDriver::BakedRunner(*tmp_binary, [&] {
      file_removed = std::filesystem::remove(*tmp_binary);
    });
  }
  ASSERT_TRUE(file_removed);
  ASSERT_FALSE(std::filesystem::exists(*tmp_binary));
}

}  // namespace
}  // namespace silifuzz
