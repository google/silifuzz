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
#include <limits>
#include <optional>
#include <random>
#include <string>
#include <vector>

#include "absl/container/btree_map.h"
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/check.h"
#include "absl/strings/str_cat.h"
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
#include "./util/hostname.h"
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
ABSL_FLAG(std::optional<absl::Duration>, time, std::nullopt,
          "Time limit for testing. For example: 1m30s. If specified, will "
          "generate and test corpora until the time limit is hit.");

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
  std::cout << "Failed to reconcile " << bad << " end states." << std::endl;

  return end_states;
}

// All the configuration needed to run a single corpus.
struct CorpusConfig {
  // A human readable name used to identify this corpus.
  std::string name;

  // The chip to generate tests for.
  xed_chip_enum_t chip;
  // The instructions to use when generating tests.
  // Held by reference to avoid copying.
  const InstructionPool& instruction_pool;
  // The number of tests to generate.
  size_t num_tests;

  // Test entry states.
  absl::Span<const Input> inputs;

  // How the tests should be run.
  RunConfig run_config;
};

// The results of running a corpus.
struct CorpusStats {
  // Time consumed generated the test code.
  absl::Duration code_gen_time;
  // Time consumed determining the end state of each test.
  absl::Duration end_state_gen_time;
  // Time consumed running the tests.
  absl::Duration test_time;

  // The number of different tests that were run.
  size_t distinct_tests;
  // The number of times a test was run.
  size_t test_instance_run;
  // The number of times all the tests iterated.
  size_t test_iteration_run;
  // The number of tests that did not produce the expected end state.
  size_t test_instance_hit;
};

void RunTestCorpus(size_t test_index, Rng& test_rng,
                   ParallelWorkerPool& workers,
                   const CorpusConfig& corpus_config, CorpusStats& corpus_stats,
                   ResultReporter& result) {
  // Generate tests corpus.
  std::cout << std::endl;
  std::cout << "Generating " << corpus_config.num_tests << " tests / "
            << corpus_config.name << std::endl;
  absl::Time begin = absl::Now();

  // Allocate the corpus.
  Corpus corpus = AllocateCorpus(test_rng, corpus_config.num_tests);

  // Generate the tests in parallel.
  // TODO(ncbray): generate tests redundantly to catch SDCs?
  struct SynthesizeTestsTask {
    absl::Span<Test> tests;
    uint8_t* code_buffer;
    size_t used;
  };
  std::vector<SynthesizeTestsTask> tasks(workers.NumWorkers());
  for (size_t i = 0; i < tasks.size(); ++i) {
    TestPartition partition =
        GetParition(i, corpus_config.num_tests, workers.NumWorkers());
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
    task.used =
        SynthesizeTests(task.tests, task.code_buffer, corpus_config.chip,
                        corpus_config.instruction_pool);
  });

  // Calculate the amount of memory used.
  size_t used = 0;
  for (const SynthesizeTestsTask& task : tasks) {
    used += task.used;
  }

  // Finish generating the corpus.
  FinalizeCorpus(corpus, used);

  corpus_stats.code_gen_time += absl::Now() - begin;
  std::cout << "Corpus size: " << (corpus.MemoryUse() / (1024 * 1024)) << " MB"
            << std::endl;

  // Generate test+input end states.
  std::cout << "Generating end states" << std::endl;
  begin = absl::Now();
  std::vector<EndState> end_states =
      DetermineEndStates(workers, corpus.tests, corpus_config.run_config.test,
                         corpus_config.inputs);
  corpus_stats.end_state_gen_time += absl::Now() - begin;
  std::cout << "End state size: "
            << (end_states.size() * sizeof(end_states[0]) / (1024 * 1024))
            << " MB" << std::endl;

  // Run test corpus.
  std::cout << "Running tests" << std::endl;
  begin = absl::Now();
  std::vector<ThreadStats> stats(workers.NumWorkers());
  workers.DoWork(stats, [&](ThreadStats& s) {
    RunTests(corpus.tests, corpus_config.inputs, end_states,
             corpus_config.run_config, test_index, s, result);
  });

  // Aggregate thread stats.
  for (const ThreadStats& s : stats) {
    corpus_stats.test_instance_run += s.num_run;
    corpus_stats.test_iteration_run +=
        s.num_run * corpus_config.run_config.test.num_iterations;
    corpus_stats.test_instance_hit += s.num_failed;
  }
  corpus_stats.test_time += absl::Now() - begin;
  corpus_stats.distinct_tests += corpus.tests.size();
}

void PrintCorpusStats(const std::string& name, const CorpusStats& corpus_stats,
                      size_t num_workers) {
  std::cout << std::endl;
  std::cout << "Stats / " << name << std::endl;
  std::cout << corpus_stats.code_gen_time << " generating code" << std::endl;
  std::cout << corpus_stats.end_state_gen_time << " generating end states"
            << std::endl;
  std::cout << corpus_stats.test_time << " testing" << std::endl;
  std::cout << corpus_stats.distinct_tests << " tests" << std::endl;
  std::cout << corpus_stats.test_instance_run << " runs" << std::endl;
  std::cout << (corpus_stats.test_iteration_run /
                (absl::ToDoubleSeconds(corpus_stats.test_time) * num_workers))
            << " iterations per second per core" << std::endl;
  std::cout << corpus_stats.test_instance_hit << " hits" << std::endl;
  std::cout << (corpus_stats.test_instance_hit /
                absl::ToDoubleSeconds(corpus_stats.test_time))
            << " per second hit rate" << std::endl;
  std::cout << (corpus_stats.test_instance_hit /
                (double)corpus_stats.test_instance_run)
            << " per run hit rate" << std::endl;
  std::cout << (1e9 * corpus_stats.test_instance_hit /
                (double)(corpus_stats.test_iteration_run))
            << " per billion iteration hit rate" << std::endl;
}

int TestMain(std::vector<char*> positional_args) {
  absl::Time test_started = absl::Now();
  std::cout << "Time started: " << test_started << std::endl;
  std::cout << "Start timestamp: " << absl::ToUnixMillis(test_started)
            << std::endl;
  std::cout << std::endl;

  InitXedIfNeeded();

  std::string hostname(ShortHostname());
  std::string version =
      absl::StrCat(kHashTestVersionMajor, ".", kHashTestVersionMinor, ".",
                   kHashTestVersionPatch);

  std::cout << "Host: " << hostname << std::endl;
  std::cout << "Version: " << version << std::endl;

  // Alow the platform to be overridden.
  PlatformId platform = absl::GetFlag(FLAGS_platform);
  if (platform == PlatformId::kUndefined) {
    // Default to the current platform.
    platform = CurrentPlatformId();
  }
  xed_chip_enum_t chip = PlatformIdToChip(platform);
  QCHECK_NE(chip, XED_CHIP_INVALID)
      << "Unsupported platform: " << EnumStr(platform);

  std::cout << "Platform: " << EnumStr(platform) << std::endl;

  size_t vector_width = ChipVectorRegisterWidth(chip);
  size_t mask_width = ChipMaskRegisterWidth(chip);
  std::cout << "Vector width: " << vector_width << std::endl;
  std::cout << "Mask width: " << mask_width << std::endl;

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

  std::cout << std::endl;
  std::cout << "Corpora: " << num_corpora << std::endl;
  std::cout << "Tests: " << num_tests << std::endl;
  std::cout << "Batch size: " << batch_size << std::endl;
  std::cout << "Inputs: " << num_inputs << std::endl;
  std::cout << "Repeat: " << num_repeat << std::endl;
  std::cout << "Iterations: " << num_iterations << std::endl;

  // Display seed so that we can recreate this run later, if needed.
  std::cout << std::endl;
  std::cout << "Seed: " << FormatSeed(seed) << std::endl;

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
  std::cout << std::endl;
  std::cout << "Num threads: " << cpu_list.size() << std::endl;
  CHECK_GT(cpu_list.size(), 0);

  // Create a pool of worker threads.
  ParallelWorkerPool workers(cpu_list.size());

  // Bind each worker thread to one of the available CPUs.
  workers.DoWork(cpu_list, [](int cpu) { SetCPUAffinity(cpu); });

  // Generating input entropy can be somewhat expensive, so amortize it across
  // all the tests.
  std::vector<Input> inputs = GenerateInputs(input_rng, num_inputs);

  const CorpusConfig corpus_config = {
      .name = "default",
      .chip = chip,
      .instruction_pool = ipool,
      .num_tests = num_tests,
      .inputs = inputs,
      .run_config =
          {
              .test =
                  {
                      .vector_width = vector_width,
                      .num_iterations = num_iterations,
                  },
              .batch_size = batch_size,
              .num_repeat = num_repeat,
          },
  };

  ResultReporter result(test_started);

  std::optional<absl::Duration> maybe_time = absl::GetFlag(FLAGS_time);
  if (maybe_time.has_value()) {
    result.testing_deadline = test_started + maybe_time.value();
    num_corpora = std::numeric_limits<size_t>::max();
  }

  size_t test_index = 0;
  CorpusStats corpus_stats{};
  for (size_t c = 0; c < num_corpora; ++c) {
    RunTestCorpus(test_index, test_rng, workers, corpus_config, corpus_stats,
                  result);
    test_index += corpus_config.num_tests;
    if (result.ShouldHalt()) {
      break;
    }
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
    std::cout << std::endl;
    std::cout << "Hits / " << hit_counts.size() << std::endl;
    for (const auto& [cpu, test_hits] : hit_counts) {
      std::cout << std::endl;
      std::cout << "CPU " << cpu << " / " << test_hits.size() << std::endl;
      for (const auto& [test_seed, input_hits] : test_hits) {
        size_t inputs = 0;
        size_t test_input_hits = 0;
        for (const auto& [input_seed, count] : input_hits) {
          inputs += 1;
          test_input_hits += count;
        }
        std::cout << "  " << FormatSeed(test_seed) << " / " << inputs << " / "
                  << test_input_hits << std::endl;
      }
    }
  }

  absl::Time test_ended = absl::Now();

  // Print stats.
  PrintCorpusStats(corpus_config.name, corpus_stats, workers.NumWorkers());

  std::cout << std::endl;
  std::cout << (test_hit_counts.size() / (double)corpus_stats.distinct_tests)
            << " per test hit rate" << std::endl;
  std::cout << "Total time: " << (test_ended - test_started) << std::endl;
  std::cout << "Time ended: " << test_ended << std::endl;
  std::cout << "End timestamp: " << absl::ToUnixMillis(test_ended) << std::endl;

  return corpus_stats.test_instance_hit > 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

}  // namespace

}  // namespace silifuzz

int main(int argc, char* argv[]) {
  std::vector<char*> positional_args = absl::ParseCommandLine(argc, argv);
  return silifuzz::TestMain(positional_args);
}
