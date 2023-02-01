// Copyright 2023 The SiliFuzz Authors.
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

#include "./orchestrator/orchestrator_util.h"

#include <sys/types.h>
#include <unistd.h>

#include <csignal>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "./util/subprocess.h"
#include "./util/testing/status_macros.h"
#include "./util/testing/status_matchers.h"

namespace silifuzz {
namespace {
using ::silifuzz::testing::IsOk;
using ::silifuzz::testing::StatusIs;
using ::testing::ElementsAre;
using ::testing::IsEmpty;

TEST(OrchestratorUtil, ListChildrenPids) {
  EXPECT_THAT(ListChildrenPids(getpid()), IsEmpty());
  Subprocess s;
  ASSERT_OK(s.Start({"/bin/sleep", "3600"}));
  EXPECT_THAT(ListChildrenPids(getpid()), ElementsAre(s.pid()));
  kill(s.pid(), SIGKILL);
}

TEST(OrchestratorUtil, NoThrow) {
  pid_t bogus_pid = 9999999;  // kernel.pid_max = 4194304
  EXPECT_THAT(ListChildrenPids(bogus_pid), IsEmpty());
  EXPECT_THAT(ProcessStatm(bogus_pid), StatusIs(absl::StatusCode::kNotFound));
  EXPECT_EQ(MaxRunnerRssSizeBytes(bogus_pid), 0);
}

TEST(OrchestratorUtil, ProcessStatm) {
  auto stat = ProcessStatm(getpid());
  EXPECT_THAT(stat, IsOk());
  EXPECT_GT(stat->rss_bytes, 0);
  EXPECT_GT(stat->vm_size_bytes, 0);
}

TEST(OrchestratorUtil, MaxRunnerRssSizeBytes) {
#if defined(ABSL_HAVE_THREAD_SANITIZER)
  GTEST_SKIP() << "This test does not work under TSAN";
#endif
  Subprocess s;
  ASSERT_OK(s.Start({"/bin/sleep", "3600"}));
  EXPECT_GT(MaxRunnerRssSizeBytes(getpid(), "sleep"), 0);
  kill(s.pid(), SIGKILL);
}

}  // namespace
}  // namespace silifuzz
