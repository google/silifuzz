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

#include "absl/container/btree_map.h"
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/check.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "./fuzzer/hashtest/hashtest_runner.h"
#include "./fuzzer/hashtest/instruction_pool.h"
#include "./fuzzer/hashtest/parallel_worker_pool.h"
#include "./fuzzer/hashtest/synthesize_base.h"
#include "./fuzzer/hashtest/version.h"
#include "./instruction/xed_util.h"
#include "./util/cpu_id.h"
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

// A list of tests to compute end states for.
struct EndStateSubtask {
  absl::Span<const Test> tests;
  absl::Span<EndState> end_states;
};

// Three lists of tests to compute end states for.
struct EndStateTask {
  absl::Span<const Input> inputs;
  EndStateSubtask subtask0;
  EndStateSubtask subtask1;
  EndStateSubtask subtask2;
};

struct TestPartition {
  // The first test included in the partition.
  size_t offset;
  // The number of tests in the partition.
  size_t size;
};

// Divide the tests into `num_workers` groups and returns the `index`-th group
// of tests.
TestPartition GetParition(int index, size_t num_tests, size_t num_workers) {
  CHECK_LT(index, num_workers);
  size_t remainder = num_tests % num_workers;
  size_t tests_in_chunk = num_tests / num_workers;
  if (index < remainder) {
    // The first `remainder` partitions have `tests_in_chunk` + 1 tests.
    return TestPartition{
        .offset = index * (tests_in_chunk + 1),
        .size = tests_in_chunk + 1,
    };
  } else {
    // The rest of the partitions have `tests_in_chunk` tests.
    return TestPartition{
        .offset = index * tests_in_chunk + remainder,
        .size = tests_in_chunk,
    };
  }
}

EndStateSubtask MakeSubtask(int index, size_t num_inputs, size_t num_workers,
                            absl::Span<const Test> tests,
                            absl::Span<EndState> end_states) {
  TestPartition partition = GetParition(index, tests.size(), num_workers);

  return {
      .tests = tests.subspan(partition.offset, partition.size),
      .end_states = absl::MakeSpan(end_states)
                        .subspan(partition.offset * num_inputs,
                                 partition.size * num_inputs),
  };
}

// For each test and input, compute an end state.
// We compute each end state 3x, and choose an end state that occurred more than
// once. If all the end states are different, the end state is marked as bad and
// that test+input combination will be skipped when running tests.
// In the future we will compute end states on different CPUs to reduce the
// chance of the same data corruption occurring multiple times.
std::vector<EndState> DetermineEndStates(ParallelWorkerPool& workers,
                                         const absl::Span<const Test> tests,
                                         const TestConfig& config,
                                         const absl::Span<const Input> inputs) {
  const size_t num_end_state = tests.size() * inputs.size();

  // Redundant sets of end states.
  std::vector<EndState> end_states(num_end_state);
  std::vector<EndState> compare1(num_end_state);
  std::vector<EndState> compare2(num_end_state);

  size_t num_workers = workers.NumWorkers();

  // Partition work.
  std::vector<EndStateTask> tasks(num_workers);
  for (size_t i = 0; i < num_workers; ++i) {
    EndStateTask& task = tasks[i];
    task.inputs = inputs;

    // For each of the redundant set of end states, compute a different
    // partition on this core.
    // Generating end states is pretty fast. The reason we're doing it on
    // multiple cores is to try and ensure (to the greatest extent possible)
    // that different cores are computing each redudnant version of the end
    // state. This makes it unlikely that the same SDC will corrupt the end
    // state twice. In cases where we are running on fewer than three cores,
    // some of the redundant end states will be computed on the same core.
    task.subtask0 = MakeSubtask(i, inputs.size(), num_workers, tests,
                                absl::MakeSpan(end_states));
    task.subtask1 = MakeSubtask((i + 1) % num_workers, inputs.size(),
                                num_workers, tests, absl::MakeSpan(compare1));
    task.subtask2 = MakeSubtask((i + 2) % num_workers, inputs.size(),
                                num_workers, tests, absl::MakeSpan(compare2));
  }

  // Execute.
  workers.DoWork(tasks, [&](EndStateTask& task) {
    ComputeEndStates(task.subtask0.tests, config, task.inputs,
                     task.subtask0.end_states);
    ComputeEndStates(task.subtask1.tests, config, task.inputs,
                     task.subtask1.end_states);
    ComputeEndStates(task.subtask2.tests, config, task.inputs,
                     task.subtask2.end_states);
  });

  // Try to guess which end states are correct, based on the redundancy.
  size_t bad =
      ReconcileEndStates(absl::MakeSpan(end_states), compare1, compare2);
  std::cout << "Failed to reconcile " << bad << " end states." << "\n";

  return end_states;
}

int TestMain(std::vector<char*> positional_args) {
  InitXedIfNeeded();

  std::cout << "Version: " << kHashTestVersionMajor << "."
            << kHashTestVersionMinor << "." << kHashTestVersionPatch << "\n";

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

  std::vector<int> cpu_list;
  ForEachAvailableCPU([&](int cpu) { cpu_list.push_back(cpu); });
  std::cout << "\n";
  std::cout << "Num threads: " << cpu_list.size() << "\n";
  CHECK_GT(cpu_list.size(), 0);

  // Create a pool of worker threads.
  ParallelWorkerPool workers(cpu_list.size());

  // Bind each worker thread to one of the available CPUs.
  workers.DoWork(cpu_list, [](int cpu) { SetCPUAffinity(cpu); });

  absl::Duration code_gen_time;
  absl::Duration end_state_gen_time;
  absl::Duration test_time;
  size_t tests_run = 0;

  // Generating input entropy can be somewhat expensive, so amortize it across
  // all the tests.
  std::vector<Input> inputs = GenerateInputs(input_rng, num_inputs);

  ResultReporter result;

  std::vector<ThreadStats> stats(workers.NumWorkers());
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
    std::cout << "\n";
    std::cout << "Generating " << num_tests << " tests" << "\n";
    absl::Time begin = absl::Now();

    // Allocate the corpus.
    Corpus corpus = AllocateCorpus(rng, num_tests);

    // Generate the tests in parallel.
    // TODO(ncbray): generate tests redundantly to catch SDCs?
    struct SynthesizeTestsTask {
      absl::Span<Test> tests;
      uint8_t* code_buffer;
      size_t used;
    };
    std::vector<SynthesizeTestsTask> tasks(workers.NumWorkers());
    for (size_t i = 0; i < tasks.size(); ++i) {
      TestPartition partition = GetParition(i, num_tests, workers.NumWorkers());
      // Each task is given a chunk of the code mapping large enough to hold the
      // maximum code size for all the tests in the partition. In practice
      // almost all of the tests will be smaller than the maximum size and the
      // code will be packed end to end for each task to improve locality. There
      // will be gaps in the code mapping between the packed code generated by
      // each task. The size of the code buffer for each task is implicitly:
      // partition.size * kMaxTestBytes.
      uint8_t* code_buffer = reinterpret_cast<uint8_t*>(corpus.mapping.Ptr()) +
                             partition.offset * kMaxTestBytes;
      tasks[i] = {
          .tests = absl::MakeSpan(corpus.tests)
                       .subspan(partition.offset, partition.size),
          .code_buffer = code_buffer,
          .used = 0,
      };
    }
    workers.DoWork(tasks, [&](SynthesizeTestsTask& task) {
      task.used = SynthesizeTests(task.tests, task.code_buffer, chip, ipool);
    });

    // Calculate the amount of memory used.
    size_t used = 0;
    for (const SynthesizeTestsTask& task : tasks) {
      used += task.used;
    }

    // Finish generating the corpus.
    FinalizeCorpus(corpus, used);

    code_gen_time += absl::Now() - begin;
    std::cout << "Corpus size: " << (corpus.MemoryUse() / (1024 * 1024))
              << " MB" << "\n";

    // Generate test+input end states.
    std::cout << "Generating end states" << "\n";
    begin = absl::Now();
    std::vector<EndState> end_states =
        DetermineEndStates(workers, corpus.tests, config.test, inputs);
    end_state_gen_time += absl::Now() - begin;
    std::cout << "End state size: "
              << (end_states.size() * sizeof(end_states[0]) / (1024 * 1024))
              << " MB" << "\n";

    // Run test corpus.
    std::cout << "Running tests" << "\n";
    begin = absl::Now();
    // HACK: currently we don't have any per-thread state, so we're passing in
    // the cpu id. In a future change, real per-thread state will be added.
    workers.DoWork(stats, [&](ThreadStats& s) {
      RunTests(corpus.tests, inputs, end_states, config, c * num_tests, s,
               result);
    });
    test_time += absl::Now() - begin;
    tests_run += corpus.tests.size();
  }

  // Aggregate thread stats.
  size_t test_instance_run = 0;
  size_t test_instance_hit = 0;
  for (const ThreadStats& s : stats) {
    test_instance_run += s.num_run;
    test_instance_hit += s.num_failed;
  }

  // Aggregate hits.
  // Count how many times each test seed hit.
  absl::btree_map<uint64_t, size_t> test_hit_counts;
  // Group hits by CPU, then by test seed, then by input seed.
  // This allows us to display which tests are hitting on which CPU, how hard
  // they are hitting, and how sensitive they are to starting with a particular
  // initial state.
  absl::btree_map<int,
                  absl::btree_map<uint64_t, absl::btree_map<uint64_t, size_t>>>
      hit_counts;
  for (const Hit& hit : result.hits) {
    ++test_hit_counts[hit.test_seed];
    ++hit_counts[hit.cpu][hit.test_seed][hit.input_seed];
  }

  if (!hit_counts.empty()) {
    std::cout << "\n";
    std::cout << "Hits / " << hit_counts.size() << "\n";
    for (const auto& [cpu, test_hits] : hit_counts) {
      std::cout << "\n";
      std::cout << "CPU " << cpu << " / " << test_hits.size() << "\n";
      for (const auto& [test_seed, input_hits] : test_hits) {
        size_t inputs = 0;
        size_t test_input_hits = 0;
        for (const auto& [input_seed, count] : input_hits) {
          inputs += 1;
          test_input_hits += count;
        }
        std::cout << "  " << FormatSeed(test_seed) << " / " << inputs << " / "
                  << test_input_hits << "\n";
      }
    }
  }

  // Print stats.
  std::cout << "\n";
  std::cout << "Stats" << "\n";
  std::cout << code_gen_time << " generating code" << "\n";
  std::cout << end_state_gen_time << " generating end states" << "\n";
  std::cout << test_time << " testing" << "\n";
  std::cout << tests_run << " tests" << "\n";
  std::cout << test_instance_run << " runs" << "\n";
  std::cout << (test_instance_run * num_iterations /
                (absl::ToDoubleSeconds(test_time) * workers.NumWorkers()))
            << " iterations per second per core" << "\n";
  std::cout << test_instance_hit << " hits" << "\n";
  std::cout << (test_instance_hit / absl::ToDoubleSeconds(test_time))
            << " per second hit rate" << "\n";
  std::cout << (test_instance_hit / (double)test_instance_run)
            << " per run hit rate" << "\n";
  std::cout << (1e9 * test_instance_hit /
                (double)(test_instance_run * num_iterations))
            << " per billion iteration hit rate" << "\n";
  std::cout << (test_hit_counts.size() / (double)tests_run)
            << " per test hit rate" << "\n";

  return test_instance_hit > 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

}  // namespace

}  // namespace silifuzz

int main(int argc, char* argv[]) {
  std::vector<char*> positional_args = absl::ParseCommandLine(argc, argv);
  return silifuzz::TestMain(positional_args);
}
