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

#include "./orchestrator/silifuzz_orchestrator.h"

#include <string>
#include <thread>  // NOLINT
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "./runner/driver/runner_driver.h"

namespace silifuzz {
namespace {
using testing::Contains;
using testing::ElementsAre;
using testing::IsSupersetOf;

TEST(ExecutionContext, Simple) {
  int results_processed = 0;
  ExecutionContext ctx(absl::InfiniteFuture(), 1,
                       [&results_processed](const RunnerDriver::RunResult& r) {
                         results_processed++;
                       });
  ASSERT_TRUE(ctx.OfferRunResult(RunnerDriver::RunResult::Successful()));
  ASSERT_FALSE(ctx.ShouldStop());
  EXPECT_EQ(results_processed, 0);
  ctx.ProcessResultQueue();
  EXPECT_EQ(results_processed, 1);
}

TEST(ExecutionContext, Expired) {
  ExecutionContext ctx(absl::InfinitePast(), 1,
                       [](const RunnerDriver::RunResult& r) {});
  ASSERT_TRUE(ctx.ShouldStop());
}

TEST(ExecutionContext, QueueSizeLimit) {
  ExecutionContext ctx(absl::InfiniteFuture(), 1,
                       [](const RunnerDriver::RunResult& r) {});
  ASSERT_TRUE(ctx.OfferRunResult(RunnerDriver::RunResult::Successful()));
  ASSERT_FALSE(ctx.OfferRunResult(RunnerDriver::RunResult::Successful()));
  ctx.ProcessResultQueue();
}

TEST(ExecutionContext, Multithreaded) {
  int results_processed = 0;
  int posted = 0;
  ExecutionContext ctx(absl::InfiniteFuture(), 5,
                       [&results_processed](const RunnerDriver::RunResult& r) {
                         results_processed++;
                       });
  std::thread worker([&ctx, &posted]() {
    while (!ctx.ShouldStop()) {
      if (ctx.OfferRunResult(RunnerDriver::RunResult::Successful())) {
        posted++;
      }
      absl::SleepFor(absl::Milliseconds(100));
    }
  });
  std::thread alarm([&ctx]() {
    absl::SleepFor(absl::Seconds(1));
    ctx.Stop();
  });
  ctx.EventLoop();
  alarm.join();
  worker.join();
  ctx.ProcessResultQueue();
  ASSERT_TRUE(ctx.ShouldStop());
  ASSERT_EQ(posted, results_processed);
  ASSERT_GT(posted, 0);
}

TEST(NextCorpusGenerator, Sequential) {
  NextCorpusGenerator gen({"1", "2", "3"}, true, 0);
  std::vector<std::string> actual;
  for (int i = 0; i < 5; ++i) {
    actual.push_back(gen());
  }
  ASSERT_THAT(actual, ElementsAre("1", "2", "3", "", ""));
}

TEST(NextCorpusGenerator, Random) {
  std::vector<std::string> src = {"1", "2", "3"};
  std::vector<std::string> result;
  NextCorpusGenerator gen(src, false, 0);
  std::vector<std::string> actual;
  for (int i = 0; i < 100; ++i) {
    std::string v = gen();
    result.push_back(v);
    ASSERT_THAT(src, Contains(v));
  }
  ASSERT_THAT(result, IsSupersetOf(src))
      << "Expected a sequence of a 100 random elements to contain each element "
         "of the source at least once";
}

}  // namespace

}  // namespace silifuzz
