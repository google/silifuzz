// Copyright 2025 The SiliFuzz Authors.
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

#include "./orchestrator/execution_context.h"

#include <thread>  // NOLINT

#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "./runner/driver/runner_driver.h"

namespace silifuzz {

namespace {

using CpuExecutionContext = ExecutionContext<RunnerDriver::RunResult>;

TEST(ExecutionContext, Simple) {
  int results_processed = 0;
  CpuExecutionContext ctx(
      absl::InfiniteFuture(), 1,
      [&results_processed](const RunnerDriver::RunResult& r) {
        results_processed++;
        return false;
      });
  ASSERT_TRUE(ctx.OfferRunResult(RunnerDriver::RunResult::Successful({})));
  ASSERT_FALSE(ctx.ShouldStop());
  EXPECT_EQ(results_processed, 0);
  ctx.ProcessResultQueue();
  EXPECT_EQ(results_processed, 1);
}

TEST(ExecutionContext, Expired) {
  CpuExecutionContext ctx(
      absl::InfinitePast(), 1,
      [](const RunnerDriver::RunResult& r) { return false; });
  ASSERT_TRUE(ctx.ShouldStop());
}

TEST(ExecutionContext, StopFast) {
  CpuExecutionContext ctx(
      absl::InfiniteFuture(), 1,
      [](const RunnerDriver::RunResult& r) { return true; });
  ASSERT_FALSE(ctx.ShouldStop());
  ASSERT_TRUE(ctx.OfferRunResult(RunnerDriver::RunResult::Successful({})));
  ctx.ProcessResultQueue();
  ASSERT_TRUE(ctx.ShouldStop());
}

TEST(ExecutionContext, QueueSizeLimit) {
  CpuExecutionContext ctx(
      absl::InfiniteFuture(), 1,
      [](const RunnerDriver::RunResult& r) { return false; });
  ASSERT_TRUE(ctx.OfferRunResult(RunnerDriver::RunResult::Successful({})));
  ASSERT_FALSE(ctx.OfferRunResult(RunnerDriver::RunResult::Successful({})));
  ctx.ProcessResultQueue();
}

TEST(ExecutionContext, Multithreaded) {
  int results_processed = 0;
  int posted = 0;
  CpuExecutionContext ctx(
      absl::InfiniteFuture(), 5,
      [&results_processed](const RunnerDriver::RunResult& r) {
        results_processed++;
        return false;
      });
  std::thread worker([&ctx, &posted]() {
    while (!ctx.ShouldStop()) {
      if (ctx.OfferRunResult(RunnerDriver::RunResult::Successful({}))) {
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

}  // namespace

}  // namespace silifuzz
