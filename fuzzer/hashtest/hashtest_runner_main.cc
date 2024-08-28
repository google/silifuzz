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

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <optional>
#include <random>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/check.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "./fuzzer/hashtest/hashtest_runner.h"
#include "./fuzzer/hashtest/instruction_pool.h"
#include "./fuzzer/hashtest/synthesize_base.h"
#include "./instruction/xed_util.h"
#include "./util/enum_flag_types.h"
#include "./util/itoa.h"
#include "./util/platform.h"

ABSL_FLAG(silifuzz::PlatformId, platform, silifuzz::PlatformId::kUndefined,
          "Platform to generate tests for. Defaults to the current platform.");
ABSL_FLAG(size_t, corpora, 1, "Number of test corpora to generate.");
ABSL_FLAG(size_t, tests, 10000, "Number of tests in a copus.");
ABSL_FLAG(size_t, batch, 10,
          "Number of different tests to run interleaved in a group.");
ABSL_FLAG(size_t, inputs, 10, "Number of different inputs for each test.");
ABSL_FLAG(size_t, repeat, 10,
          "Number of times to repeat each test+input combination.");
ABSL_FLAG(size_t, iterations, 100,
          "Number of internal iterations for each test.");
ABSL_FLAG(std::optional<uint64_t>, seed, std::nullopt,
          "Fixed seed to use for random number generation.");

ABSL_FLAG(bool, verbose, false, "Print additional debugging information.");

namespace silifuzz {

namespace {

std::vector<Input> GenerateInputs(Rng& rng, size_t num_inputs) {
  std::vector<Input> inputs;
  inputs.resize(num_inputs);
  for (size_t i = 0; i < num_inputs; i++) {
    uint64_t seed = GetSeed(rng);
    inputs[i].seed = seed;
    RandomizeEntropyBuffer(seed, inputs[i].entropy);
  }
  return inputs;
}

// For each test and input, compute an end state.
// We compute each end state 3x, and choose an end state that occurred more than
// once. If all the end states are different, the end state is marked as bad and
// that test+input combination will be skipped when running tests.
// In the future we will compute end states on different CPUs to reduce the
// chance of the same data corruption occurring multiple times.
std::vector<EndState> DetermineEndStates(const absl::Span<const Test> tests,
                                         const TestConfig& config,
                                         const absl::Span<const Input> inputs) {
  const size_t num_end_state = tests.size() * inputs.size();

  std::vector<EndState> end_states(num_end_state);
  std::vector<EndState> compare1(num_end_state);
  std::vector<EndState> compare2(num_end_state);

  ComputeEndStates(tests, config, inputs, absl::MakeSpan(end_states));
  ComputeEndStates(tests, config, inputs, absl::MakeSpan(compare1));
  ComputeEndStates(tests, config, inputs, absl::MakeSpan(compare2));

  ReconcileEndStates(absl::MakeSpan(end_states), compare1, compare2);

  return end_states;
}

int TestMain(std::vector<char*> positional_args) {
  InitXedIfNeeded();

  // Alow the platform to be overridden.
  PlatformId platform = absl::GetFlag(FLAGS_platform);
  if (platform == PlatformId::kUndefined) {
    // Default to the current platform.
    platform = CurrentPlatformId();
  }
  xed_chip_enum_t chip = PlatformIdToChip(platform);
  QCHECK_NE(chip, XED_CHIP_INVALID)
      << "Unsupported platform: " << EnumStr(platform);

  std::cout << "Platform: " << EnumStr(platform) << "\n";

  size_t vector_width = ChipVectorRegisterWidth(chip);
  std::cout << "Vector width: " << vector_width << "\n";
  std::cout << "Mask width: " << ChipMaskRegisterWidth(chip) << "\n";

  size_t num_corpora = absl::GetFlag(FLAGS_corpora);
  size_t num_tests = absl::GetFlag(FLAGS_tests);
  size_t num_inputs = absl::GetFlag(FLAGS_inputs);
  size_t num_repeat = absl::GetFlag(FLAGS_repeat);
  size_t num_iterations = absl::GetFlag(FLAGS_iterations);
  size_t batch_size = absl::GetFlag(FLAGS_batch);
  bool verbose = absl::GetFlag(FLAGS_verbose);

  // Either get a fixed seed or generate a random seed.
  std::optional<uint64_t> maybe_seed = absl::GetFlag(FLAGS_seed);
  std::random_device hardware_rng{};
  uint64_t seed = maybe_seed.value_or(GetSeed(hardware_rng));

  std::cout << "\n";
  std::cout << "Corpora: " << num_corpora << "\n";
  std::cout << "Tests: " << num_tests << "\n";
  std::cout << "Batch size: " << batch_size << "\n";
  std::cout << "Inputs: " << num_inputs << "\n";
  std::cout << "Repeat: " << num_repeat << "\n";
  std::cout << "Iterations: " << num_iterations << "\n";

  // Display seed so that we can recreate this run later, if needed.
  std::cout << "\n";
  std::cout << "Seed: " << FormatSeed(seed) << "\n";

  // Create separate test and input RNGs so that we can get predictable
  // sequences, given a fixed seed. If we don't do this, small changes to the
  // program could wildly perturb the tests generated, etc.
  Rng rng(seed);
  Rng test_rng(GetSeed(rng));
  Rng input_rng(GetSeed(rng));

  // Find the instructions that are valid for this chip.
  InstructionPool ipool{};
  GenerateInstructionPool(rng, chip, ipool, verbose);

  absl::Duration code_gen_time;
  absl::Duration end_state_gen_time;
  absl::Duration test_time;
  size_t test_instance_run = 0;
  size_t test_instance_hit = 0;
  size_t tests_run = 0;
  size_t test_hits = 0;

  // Generating input entropy can be somewhat expensive, so amortize it across
  // all the tests.
  std::vector<Input> inputs = GenerateInputs(input_rng, num_inputs);

  ResultReporter result;
  absl::Time begin;

  std::cout << "\n";
  for (size_t c = 0; c < num_corpora; ++c) {
    RunConfig config = {
        .test =
            {
                .vector_width = vector_width,
                .num_iterations = num_iterations,
            },
        .batch_size = batch_size,
        .num_repeat = num_repeat,
    };

    // Generate tests corpus.
    std::cout << "Generating " << num_tests << " tests" << "\n";
    begin = absl::Now();
    Corpus corpus = SynthesizeCorpus(test_rng, chip, ipool, num_tests, verbose);
    code_gen_time += absl::Now() - begin;
    std::cout << "Corpus size: " << (corpus.MemoryUse() / (1024 * 1024))
              << " MB" << "\n";

    // Generate test+input end states.
    std::cout << "Generating end states" << "\n";
    begin = absl::Now();
    std::vector<EndState> end_states =
        DetermineEndStates(corpus.tests, config.test, inputs);
    end_state_gen_time += absl::Now() - begin;
    std::cout << "End state size: "
              << (end_states.size() * sizeof(end_states[0]) / (1024 * 1024))
              << " MB" << "\n";

    // Run test corpus.
    begin = absl::Now();
    RunTests(corpus.tests, inputs, end_states, config, c * num_tests, result);
    test_time += absl::Now() - begin;

    // Count how many times each test hit.
    // TODO(ncbray): use unordered_map for sparseness.
    std::vector<size_t> hit_count(corpus.tests.size());
    for (const Hit& hit : result.hits) {
      hit_count[hit.test_index]++;
    }
    test_instance_hit += result.hits.size();
    result.hits.clear();

    for (size_t t = 0; t < corpus.tests.size(); ++t) {
      // We may have failed to determine an end state and skipped the test,
      // which means we need to count the tests we did run rather than doing a
      // simple multiplication.
      size_t times_test_has_run = 0;
      for (size_t i = 0; i < inputs.size(); ++i) {
        if (!end_states[t * inputs.size() + i].CouldNotBeComputed()) {
          times_test_has_run += num_repeat;
        }
      }
      // Collect stats.
      if (times_test_has_run > 0) {
        tests_run += 1;
        if (hit_count[t] > 0) {
          test_hits += 1;
        }
        test_instance_run += times_test_has_run;
      }
    }
  }

  // Print stats.
  std::cout << "\n";
  std::cout << "Stats" << "\n";
  std::cout << code_gen_time << " generating code" << "\n";
  std::cout << end_state_gen_time << " generating end states" << "\n";
  std::cout << test_time << " testing" << "\n";
  std::cout << num_corpora * num_tests << " tests" << "\n";
  std::cout << test_instance_run << " runs" << "\n";
  std::cout << test_instance_hit << " hits" << "\n";
  std::cout << (test_instance_hit / absl::ToDoubleSeconds(test_time))
            << " per second hit rate" << "\n";
  std::cout << (test_instance_hit / (double)test_instance_run)
            << " per run hit rate" << "\n";
  std::cout << (1e9 * test_instance_hit /
                (double)(test_instance_run * num_iterations))
            << " per billion iteration hit rate" << "\n";
  std::cout << (test_hits / (double)tests_run) << " per test hit rate" << "\n";

  return test_instance_hit > 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

}  // namespace

}  // namespace silifuzz

int main(int argc, char* argv[]) {
  std::vector<char*> positional_args = absl::ParseCommandLine(argc, argv);
  return silifuzz::TestMain(positional_args);
}
