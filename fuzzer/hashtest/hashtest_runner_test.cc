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

#include "./fuzzer/hashtest/hashtest_runner.h"

#include <sys/types.h>

#include <cstdint>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "./fuzzer/hashtest/hashtest_runner_widgits.h"
#include "./fuzzer/hashtest/instruction_pool.h"
#include "./fuzzer/hashtest/json.h"
#include "./fuzzer/hashtest/mxcsr.h"
#include "./fuzzer/hashtest/synthesize_base.h"
#include "./fuzzer/hashtest/synthesize_test.h"
#include "./instruction/xed_util.h"
#include "./util/platform.h"

namespace silifuzz {

namespace {

// Test to validate the assumptions made in the hashtest runner.
TEST(Runner, AllSupported) {
  InitXedIfNeeded();
  for (size_t i = 0; i < static_cast<size_t>(kMaxPlatformId); i++) {
    PlatformId p = static_cast<PlatformId>(i);
    // Ivybridge machines are the only pre-AVX2 PlatformId.
    // They are pretty old, so we aren't going to worry about supporting them
    // with HashTests right now.
    if (p == PlatformId::kIntelIvybridge) {
      continue;
    }
    xed_chip_enum_t chip = PlatformIdToChip(p);
    if (chip == XED_CHIP_INVALID) {
      continue;
    }
    size_t vector_width = ChipVectorRegisterWidth(chip);
    // Currently, the runner supports 256 and 512 bit vector registers.
    EXPECT_GE(vector_width, 256) << i;
    EXPECT_LE(vector_width, 512) << i;
    // The mask registers are expected to be 64 bit, if they exist.
    if (vector_width >= 512) {
      EXPECT_EQ(ChipMaskRegisterWidth(chip), vector_width / 8) << i;
    }
  }
}

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
  // Running it should result in the input being copied to the output, although
  // bytes at the end of the input may be ignored if the vector width is not the
  // maximum.
  RunHashTest(reinterpret_cast<void*>(&NopTest), config, input, output);

  // Check that the relevant part of the buffer has been copied and the rest has
  // been left untouched.
  size_t num_bytes = input.NumBytes(vector_width);
  for (size_t i = 0; i < sizeof(output.bytes); i++) {
    EXPECT_EQ(output.bytes[i], i < num_bytes ? input.bytes[i] : 0) << i;
  }
}

TEST(Runner, Run512) {
  constexpr size_t kVectorWidth = 512;
  if (CurrentVectorWidth() < kVectorWidth) {
    GTEST_SKIP() << "Chip does not support this vector width.";
  }
  // Test with two different bit patterns.
  SmokeTest(0, kVectorWidth);
  SmokeTest(1, kVectorWidth);
}

TEST(Runner, Run256) {
  constexpr size_t kVectorWidth = 256;
  if (CurrentVectorWidth() < kVectorWidth) {
    GTEST_SKIP() << "Chip does not support this vector width.";
  }

  // Test with two different bit patterns.
  SmokeTest(2, kVectorWidth);
  SmokeTest(3, kVectorWidth);
}

TEST(Runner, Run128) {
  constexpr size_t kVectorWidth = 128;
  if (CurrentVectorWidth() < kVectorWidth) {
    GTEST_SKIP() << "Chip does not support this vector width.";
  }

  // Test with two different bit patterns.
  SmokeTest(4, kVectorWidth);
  SmokeTest(5, kVectorWidth);
}

TEST(Runner, EndToEnd) {
  InitXedIfNeeded();
  xed_chip_enum_t chip = PlatformIdToChip(CurrentPlatformId());
  if (chip == XED_CHIP_INVALID) {
    GTEST_SKIP() << "Unsupported chip.";
  }

  Rng rng(0);

  const RunConfig run_config = {
      .test =
          {
              .vector_width = ChipVectorRegisterWidth(chip),
              .num_iterations = 1,
          },
      .batch_size = 1,
      .num_repeat = 1,
  };

  InstructionPool ipool{};
  GenerateInstructionPool(rng, chip, ipool, false);

  SynthesisConfig synthesis_config = {
      .ipool = &ipool,
  };

  Corpus corpus = AllocateCorpus(rng, 1);
  size_t used =
      SynthesizeTests(absl::MakeSpan(corpus.tests),
                      reinterpret_cast<uint8_t *>(corpus.mapping.Ptr()), chip,
                      synthesis_config);
  FinalizeCorpus(corpus, used);

  std::vector<Input> inputs;
  inputs.resize(1);
  RandomizeEntropyBuffer(GetSeed(rng), inputs[0].entropy);

  std::vector<EndState> end_states;
  end_states.resize(corpus.tests.size() * inputs.size());
  ComputeEndStates(corpus.tests, run_config.test, inputs,
                   absl::MakeSpan(end_states));

  ThreadStats stats{};
  ResultReporter result(absl::Now());
  absl::Duration testing_time = absl::Seconds(1);
  RunTests(corpus.tests, inputs, end_states, run_config, 0, testing_time, stats,
           result);

  EXPECT_EQ(stats.num_failed, 0);
  EXPECT_EQ(result.hits.size(), 0);
}

TEST(MXCSR, GetSet) {
  uint32_t old = GetMxcsr();

  // Set the register to two different values and read it back.
  // This proves the register can be modified, no matter the initial value.
  const uint32_t target0 = kMXCSRMaskAll | kMXCSRFlushToZero;
  SetMxcsr(target0);
  uint32_t changed0 = GetMxcsr();

  const uint32_t target1 = kMXCSRMaskAll | kMXCSRDenormalsAreZeros;
  SetMxcsr(target1);
  uint32_t changed1 = GetMxcsr();

  SetMxcsr(old);
  uint32_t restored = GetMxcsr();

  EXPECT_EQ(changed0, target0);
  EXPECT_EQ(changed1, target1);
  EXPECT_EQ(restored, old);
}

TEST(JSON, String) {
  std::stringstream buffer;
  JSONFormatter out(buffer);
  out.Value("str");
  EXPECT_EQ(buffer.str(), R"("str")");
}

TEST(JSON, EscapedString) {
  std::stringstream buffer;
  JSONFormatter out(buffer);
  out.Value("\\\n\t\r\"");
  EXPECT_EQ(buffer.str(), R"("\\\n\t\r\"")");
}

TEST(JSON, Numeric) {
  std::stringstream buffer;
  JSONFormatter out(buffer);
  out.List([&] {
    out.Value(1U).Value(2UL).Value(3).Value(4L).Value(5.6f).Value(7.8);
  });
  EXPECT_EQ(buffer.str(), R"([1,2,3,4,5.6,7.8])");
}

TEST(JSON, List) {
  std::stringstream buffer;
  JSONFormatter out(buffer);
  out.List([&] { out.List([] {}).List([] {}).List([] {}); });
  EXPECT_EQ(buffer.str(), R"([[],[],[]])");
}

TEST(JSON, Vector) {
  std::stringstream buffer;
  JSONFormatter out(buffer);
  std::vector<std::string> list{"a", "b", "c"};
  out.Value(list);
  EXPECT_EQ(buffer.str(), R"(["a","b","c"])");
}

TEST(JSON, Object) {
  std::stringstream buffer;
  JSONFormatter out(buffer);
  out.Object([&] {
    out.Field("a").Object([] {});
    out.Field("b").Object([] {});
    out.Field("c").Object([] {});
  });
  EXPECT_EQ(buffer.str(), R"({"a":{},"b":{},"c":{}})");
}

TEST(JSON, Heterogeneous) {
  std::stringstream buffer;
  JSONFormatter out(buffer);
  out.Object([&] { out.Field("a", 1).Field("b", "two"); });
  EXPECT_EQ(buffer.str(), R"({"a":1,"b":"two"})");
}

TEST(TimeEstimator, Basic) {
  TimeEstimator est{};
  absl::Time now = absl::Now();
  absl::Time deadline = now + absl::Seconds(3);
  est.Reset(now, deadline);
  EXPECT_FALSE(est.ShouldUpdate());

  // Simulate the artificial passage of time.

  constexpr size_t kRunPerSecond = 10000;

  est.num_run += kRunPerSecond;
  now += absl::Seconds(1);
  EXPECT_TRUE(est.ShouldUpdate());
  est.Update(now, deadline);
  EXPECT_EQ(est.tests_per_second, kRunPerSecond);
  EXPECT_EQ(est.num_run_target, kRunPerSecond * (1 + kUpdateInterval));
  EXPECT_FALSE(est.ShouldUpdate());

  est.num_run += kRunPerSecond;
  now += absl::Seconds(1);
  EXPECT_TRUE(est.ShouldUpdate());
  est.Update(now, deadline);
  EXPECT_EQ(est.tests_per_second, kRunPerSecond);
  EXPECT_EQ(est.num_run_target, kRunPerSecond * (2 + kUpdateInterval));
  EXPECT_FALSE(est.ShouldUpdate());

  est.num_run += kRunPerSecond;
  now += absl::Seconds(1);
  EXPECT_TRUE(est.ShouldUpdate());
  est.Update(now, deadline);
  EXPECT_EQ(est.tests_per_second, kRunPerSecond);
  // The run target should have been affected by the deadline.
  EXPECT_GE(est.num_run_target, kRunPerSecond * 3);
  EXPECT_LT(est.num_run_target, kRunPerSecond * (3 + kUpdateInterval));
}

}  // namespace

}  // namespace silifuzz
