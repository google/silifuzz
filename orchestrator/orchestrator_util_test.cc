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
#include "./util/data_dependency.h"
#include "./util/subprocess.h"
#include "./util/testing/status_macros.h"
#include "./util/testing/status_matchers.h"

namespace silifuzz {
namespace {
using ::silifuzz::testing::IsOk;
using ::silifuzz::testing::IsOkAndHolds;
using ::silifuzz::testing::StatusIs;
using ::testing::ElementsAre;
using ::testing::Gt;
using ::testing::IsEmpty;
using ::testing::SizeIs;

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

TEST(OrchestratorUtil, AvailableMemoryMb) {
  EXPECT_THAT(AvailableMemoryMb(), IsOkAndHolds(Gt(0)));
}

TEST(OrchestratorUtil, CapShardsToMemLimit) {
  std::string shard =
      GetDataDependencyFilepath("orchestrator/testdata/one_mb_of_zeros.xz");
  std::vector<std::string> shards{1, shard};
  absl::StatusOr<std::vector<std::string>> capped_shards =
      CapShardsToMemLimit(shards, /* runner size */ 512 + /* extra */ 10, 1);
  EXPECT_THAT(capped_shards, IsOkAndHolds(shards));

  shards.resize(10, shard);
  capped_shards =
      CapShardsToMemLimit(shards, /* runner size */ 512 + /* extra */ 10, 1);
  EXPECT_THAT(capped_shards, IsOkAndHolds(shards));

  shards.resize(100, shard);
  capped_shards =
      CapShardsToMemLimit(shards, /* runner size */ 512 + /* extra */ 10, 1);
  EXPECT_THAT(capped_shards, IsOkAndHolds(SizeIs(10)));

  shards.resize(1, shard);
  capped_shards =
      CapShardsToMemLimit(shards, /* runner size */ 512 + /* extra */ 0, 1);
  EXPECT_THAT(capped_shards, StatusIs(absl::StatusCode::kResourceExhausted));
}

}  // namespace
}  // namespace silifuzz
