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

#include <unistd.h>

#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
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
  std::string out;
  s.Communicate(&out);
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

TEST(OrchestratorUtil, AvailableMemoryMb) {
  EXPECT_THAT(AvailableMemoryMb(), IsOkAndHolds(Gt(0)));
}

TEST(OrchestratorUtil, CapShardsToMemLimitNotCapped1) {
  std::string shard =
      GetDataDependencyFilepath("orchestrator/testdata/one_mb_of_zeros.xz");
  std::vector<std::string> shards{1, shard};
  OrchestratorResources resources{.num_concurrent_runners = 1,
                                  .shards = shards};
  absl::Status status = CapResourcesToMemLimit(
      /* runner size */ 512 + /* extra */ 10, resources);
  EXPECT_OK(status);
  EXPECT_EQ(resources.num_concurrent_runners, 1);
  EXPECT_EQ(resources.shards, shards);
}

TEST(OrchestratorUtil, CapShardsToMemLimitNotCapped2) {
  std::string shard =
      GetDataDependencyFilepath("orchestrator/testdata/one_mb_of_zeros.xz");
  std::vector<std::string> shards{10, shard};
  OrchestratorResources resources{.num_concurrent_runners = 1,
                                  .shards = shards};
  absl::Status status = CapResourcesToMemLimit(
      /* runner size */ 512 + /* extra */ 10, resources);
  EXPECT_OK(status);
  EXPECT_EQ(resources.num_concurrent_runners, 1);
  EXPECT_EQ(resources.shards, shards);
}

TEST(OrchestratorUtil, CapShardsToMemLimitShardsCapped) {
  std::string shard =
      GetDataDependencyFilepath("orchestrator/testdata/one_mb_of_zeros.xz");
  OrchestratorResources resources{
      .num_concurrent_runners = 1,
      .shards = std::vector<std::string>{100, shard}};
  absl::Status status = CapResourcesToMemLimit(
      /* runner size */ 512 + /* extra */ 10, resources);
  EXPECT_OK(status);
  EXPECT_EQ(resources.num_concurrent_runners, 1);
  EXPECT_THAT(resources.shards, SizeIs(10));
}

TEST(OrchestratorUtil, CapShardsToMemLimitResourcesExhausted1) {
  std::string shard =
      GetDataDependencyFilepath("orchestrator/testdata/one_mb_of_zeros.xz");
  OrchestratorResources resources{.num_concurrent_runners = 1,
                                  .shards = std::vector<std::string>{1, shard}};
  absl::Status status = CapResourcesToMemLimit(
      /* runner size */ 512 + /* extra */ 0, resources);
  EXPECT_THAT(status, StatusIs(absl::StatusCode::kResourceExhausted));
}

TEST(OrchestratorUtil, CapShardsToMemLimitResourcesExhausted2) {
  std::string shard =
      GetDataDependencyFilepath("orchestrator/testdata/one_mb_of_zeros.xz");
  OrchestratorResources resources{.num_concurrent_runners = 1,
                                  .shards = std::vector<std::string>{1, shard}};
  absl::Status status = CapResourcesToMemLimit(0, resources);
  EXPECT_THAT(status, StatusIs(absl::StatusCode::kResourceExhausted));
}

TEST(OrchestratorUtil, CapShardsToMemLimitRunnersCapped) {
  // Memory limit is reached, cap with best effort to 1 runner 1 shard.
  std::string shard =
      GetDataDependencyFilepath("orchestrator/testdata/one_mb_of_zeros.xz");
  std::vector<std::string> shards{1, shard};
  OrchestratorResources resources{.num_concurrent_runners = 10,
                                  .shards = shards};
  absl::Status status = CapResourcesToMemLimit(
      /* runner size */ 512 + /* extra */ 10, resources);
  EXPECT_OK(status);
  EXPECT_EQ(resources.num_concurrent_runners, 1);
  EXPECT_EQ(resources.shards, shards);
}

TEST(OrchestratorUtil, CapShardsToMemLimitRunnersAndShardsCapped) {
  // Memory limit is reached, cap with best effort to 11 runners 22 shards.
  std::string shard =
      GetDataDependencyFilepath("orchestrator/testdata/one_mb_of_zeros.xz");
  OrchestratorResources resources{
      .num_concurrent_runners = 100,
      .shards = std::vector<std::string>{100, shard}};
  absl::Status status = CapResourcesToMemLimit(
      /* runner size */ 512 * 11 + /* extra */ 22, resources);
  EXPECT_OK(status);
  EXPECT_EQ(resources.num_concurrent_runners, 11);
  EXPECT_THAT(resources.shards, SizeIs(22));
}

}  // namespace
}  // namespace silifuzz
