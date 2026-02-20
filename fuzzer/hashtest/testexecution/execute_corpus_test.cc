// Copyright 2024 The Silifuzz Authors.
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

#include "./fuzzer/hashtest/testexecution/execute_corpus.h"

#include <sys/types.h>

#include <cstdint>
#include <cstring>
#include <string>

#include "gtest/gtest.h"
#include "absl/time/time.h"
#include "./fuzzer/hashtest/entropy.h"
#include "./fuzzer/hashtest/parallel_worker_pool.h"
#include "./fuzzer/hashtest/runnable_corpus.h"
#include "./fuzzer/hashtest/testexecution/hashtest_runner_widgits.h"
#include "./fuzzer/hashtest/testgeneration/corpus_generator.h"
#include "./fuzzer/hashtest/versioning/tested_corpus_configs.h"
#include "./instruction/xed_util.h"
#include "./util/platform.h"

namespace silifuzz {

namespace {

constexpr RunConfig kRunConfig = {
    .test =
        {
            .vector_width = 128,
            .num_iterations = 10,
        },
    .batch_size = 4,
    .num_repeat = 3,
};

size_t CurrentVectorWidth() {
  InitXedIfNeeded();
  PlatformId platform = CurrentPlatformId();
  xed_chip_enum_t chip = PlatformIdToChip(platform);
  size_t vector_width =
      chip != XED_CHIP_INVALID ? ChipVectorRegisterWidth(chip) : 0;
  return vector_width;
}

void SmokeTest(uint64_t seed, size_t vector_width) {
  TestConfig config = {
      .vector_width = vector_width,
      .num_iterations = 1,
  };
  EntropyBuffer input = {};
  EntropyBuffer output = {};
  RandomizeEntropyBuffer(seed, input);

  // NopTest should leave the registers undisturbed.
  // Running it should result in the input being copied to the output,
  // although bytes at the end of the input may be ignored if the vector width
  // is not the maximum.
  RunHashTest(reinterpret_cast<void*>(&NopTest), config, input, output);

  // Check that the relevant part of the buffer has been copied and the rest has
  // been left untouched.
  size_t num_bytes = input.NumBytes(vector_width);
  for (size_t i = 0; i < sizeof(output.bytes); i++) {
    EXPECT_EQ(output.bytes[i], i < num_bytes ? input.bytes[i] : 0) << i;
  }
}

RunnableCorpus GenerateCorpusForExecution(ParallelWorkerPool& worker_pool) {
  InitXedIfNeeded();
  CorpusGenerator corpus_generator;

  GenerationConfig config = kBasicConfig;
  config.chip = PlatformIdToChip(CurrentPlatformId());

  return corpus_generator.GenerateCorpusForConfig(kBasicConfig, worker_pool);
}

TEST(RunHashTest, Run512) {
  constexpr size_t kVectorWidth = 512;
  if (CurrentVectorWidth() < kVectorWidth) {
    GTEST_SKIP() << "Chip does not support this vector width.";
  }
  // Test with two different bit patterns.
  SmokeTest(0, kVectorWidth);
  SmokeTest(1, kVectorWidth);
}

TEST(RunHashTest, Run256) {
  constexpr size_t kVectorWidth = 256;
  if (CurrentVectorWidth() < kVectorWidth) {
    GTEST_SKIP() << "Chip does not support this vector width.";
  }

  // Test with two different bit patterns.
  SmokeTest(2, kVectorWidth);
  SmokeTest(3, kVectorWidth);
}

TEST(RunHashTest, Run128) {
  constexpr size_t kVectorWidth = 128;
  if (CurrentVectorWidth() < kVectorWidth) {
    GTEST_SKIP() << "Chip does not support this vector width.";
  }

  // Test with two different bit patterns.
  SmokeTest(4, kVectorWidth);
  SmokeTest(5, kVectorWidth);
}

TEST(CorpusExecutionTests, EachThreadGetsAPerThreadExecutionStat) {
  ParallelWorkerPool workers(4);
  RunnableCorpus corpus = GenerateCorpusForExecution(workers);

  EXPECT_EQ(GenerateEndStatesForCorpus(kRunConfig, corpus, workers), 0);

  auto per_thread_stats = ExecuteCorpus(corpus, kRunConfig, absl::Seconds(1), 0,
                                        ExecutionStopper(), workers);

  EXPECT_EQ(per_thread_stats.size(), 4);
}

}  // namespace

}  // namespace silifuzz
