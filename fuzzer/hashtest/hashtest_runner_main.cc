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

#include <signal.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <iterator>
#include <optional>
#include <random>
#include <string>
#include <utility>
#include <vector>

#include "google/protobuf/timestamp.pb.h"
#include "absl/container/btree_map.h"
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/check.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "./fuzzer/hashtest/hashtest_result.pb.h"
#include "./fuzzer/hashtest/hashtest_runner.h"
#include "./fuzzer/hashtest/json.h"
#include "./fuzzer/hashtest/parallel_worker_pool.h"
#include "./fuzzer/hashtest/testgeneration/candidate.h"
#include "./fuzzer/hashtest/testgeneration/instruction_pool.h"
#include "./fuzzer/hashtest/testgeneration/mxcsr.h"
#include "./fuzzer/hashtest/testgeneration/synthesize_base.h"
#include "./fuzzer/hashtest/testgeneration/synthesize_test.h"
#include "./fuzzer/hashtest/testgeneration/version.h"
#include "./instruction/xed_util.h"
#include "./util/cpu_id.h"
#include "./util/enum_flag_types.h"
#include "./util/hostname.h"
#include "./util/itoa.h"
#include "./util/platform.h"
#include "./util/time_proto_util.h"

ABSL_FLAG(silifuzz::PlatformId, platform, silifuzz::PlatformId::kUndefined,
          "Platform to generate tests for. Defaults to the current platform.");
ABSL_FLAG(size_t, j, 0,
          "Maximum number of cores to test. Will test all available cores, by "
          "default.");
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
ABSL_FLAG(absl::Duration, corpus_time, absl::Seconds(10),
          "Time limit for generating and running a single corpus. For example: "
          "1m30s.");
ABSL_FLAG(absl::Duration, time, absl::Minutes(1),
          "Total time limit for testing. For example: 1m30s.");
ABSL_FLAG(bool, print_proto, false,
          "Dump a binary proto to stdout rather than text. Intended for cases "
          "where a machine-readable result is needed.");
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
                                         const absl::Span<const Input> inputs,
                                         bool printing_allowed) {
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
  if (printing_allowed && bad > 0) {
    std::cout << "Failed to reconcile " << bad << " end states." << std::endl;
  }

  return end_states;
}

// All the configuration needed to run a single corpus.
struct CorpusConfig {
  // A human readable name used to identify this corpus.
  std::string name;

  // A list of strings identifying what experiments are active.
  std::vector<std::string> tags;

  // The chip to generate tests for.
  xed_chip_enum_t chip;

  // Settings for test synthesis.
  SynthesisConfig synthesis_config;

  // The number of tests to generate.
  size_t num_tests;

  // Test entry states.
  absl::Span<const Input> inputs;

  // How the tests should be run.
  RunConfig run_config;
};

std::string TagsToName(const std::vector<std::string>& tags) {
  if (tags.empty()) {
    return "default";
  }
  return absl::StrJoin(tags, ":");
}

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

  CorpusStats& operator+=(const CorpusStats& other) {
    code_gen_time += other.code_gen_time;
    end_state_gen_time += other.end_state_gen_time;
    test_time += other.test_time;
    distinct_tests += other.distinct_tests;
    test_instance_run += other.test_instance_run;
    test_iteration_run += other.test_iteration_run;
    test_instance_hit += other.test_instance_hit;
    return *this;
  }
};

void RunTestCorpus(size_t test_index, Rng& test_rng,
                   ParallelWorkerPool& workers,
                   const CorpusConfig& corpus_config, CorpusStats& corpus_stats,
                   absl::Duration run_time, ResultReporter& result,
                   bool printing_allowed) {
  // Generate tests corpus.
  if (printing_allowed) {
    std::cout << std::endl;
    std::cout << "Generating " << corpus_config.num_tests << " tests / "
              << corpus_config.name << std::endl;
  }
  absl::Time corpus_begin = absl::Now();

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
                        corpus_config.synthesis_config);

    // Needs to be set on each worker thread.
    // Affects end state generation and test running.
    SetMxcsr(corpus_config.run_config.mxcsr);
  });

  // Calculate the amount of memory used.
  size_t used = 0;
  for (const SynthesizeTestsTask& task : tasks) {
    used += task.used;
  }

  // Finish generating the corpus.
  FinalizeCorpus(corpus, used);

  if (printing_allowed) {
    std::cout << "Corpus size: " << (corpus.MemoryUse() / (1024 * 1024))
              << " MB" << std::endl;
  }

  absl::Time end_state_begin = absl::Now();
  corpus_stats.code_gen_time += end_state_begin - corpus_begin;

  // Generate test+input end states.
  if (printing_allowed) {
    std::cout << "Generating end states" << std::endl;
  }
  std::vector<EndState> end_states =
      DetermineEndStates(workers, corpus.tests, corpus_config.run_config.test,
                         corpus_config.inputs, printing_allowed);
  if (printing_allowed) {
    std::cout << "End state size: "
              << (end_states.size() * sizeof(end_states[0]) / (1024 * 1024))
              << " MB" << std::endl;
  }

  absl::Time test_begin = absl::Now();
  corpus_stats.end_state_gen_time += test_begin - end_state_begin;

  // Run test corpus.
  if (printing_allowed) {
    std::cout << "Running tests" << std::endl;
  }
  std::vector<ThreadStats> stats(workers.NumWorkers());
  absl::Duration testing_time = run_time - (test_begin - corpus_begin);
  workers.DoWork(stats, [&](ThreadStats& s) {
    RunTests(corpus.tests, corpus_config.inputs, end_states,
             corpus_config.run_config, test_index, testing_time, s, result);
  });

  // Aggregate thread stats.
  for (const ThreadStats& s : stats) {
    corpus_stats.test_instance_run += s.num_run;
    corpus_stats.test_iteration_run +=
        s.num_run * corpus_config.run_config.test.num_iterations;
    corpus_stats.test_instance_hit += s.num_failed;
  }
  corpus_stats.test_time += absl::Now() - test_begin;
  corpus_stats.distinct_tests += corpus.tests.size();
}

void FormatTestConfigJSON(const TestConfig& test_config, JSONFormatter& out) {
  out.Object([&] {
    out.Field("vector_width", test_config.vector_width);
    out.Field("num_iterations", test_config.num_iterations);
  });
}

void FormatRunConfigJSON(const RunConfig& run_config, JSONFormatter& out) {
  out.Object([&] {
    out.Field("test");
    FormatTestConfigJSON(run_config.test, out);
    out.Field("batch_size", run_config.batch_size);
    out.Field("num_repeat", run_config.num_repeat);
    out.Field("mxcsr", run_config.mxcsr);
  });
}

void FormatCorpusConfigJSON(const CorpusConfig& corpus_config,
                            JSONFormatter& out) {
  out.Object([&] {
    out.Field("name", corpus_config.name);
    out.Field("tags", corpus_config.tags);
    out.Field("chip", xed_chip_enum_t2str(corpus_config.chip));
    out.Field("num_tests", corpus_config.num_tests);
    out.Field("num_inputs", corpus_config.inputs.size());
    out.Field("run_config");
    FormatRunConfigJSON(corpus_config.run_config, out);
  });
}

void FormatCorpusStatsJSON(const CorpusStats& corpus_stats,
                           JSONFormatter& out) {
  out.Object([&] {
    out.Field("code_gen_time",
              absl::ToDoubleSeconds(corpus_stats.code_gen_time));
    out.Field("end_state_gen_time",
              absl::ToDoubleSeconds(corpus_stats.end_state_gen_time));
    out.Field("test_time", absl::ToDoubleSeconds(corpus_stats.test_time));
    out.Field("distinct_tests", corpus_stats.distinct_tests);
    out.Field("test_instance_run", corpus_stats.test_instance_run);
    out.Field("test_iteration_run", corpus_stats.test_iteration_run);
    out.Field("test_instance_hit", corpus_stats.test_instance_hit);
  });
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

void SetTestTimes(proto::HashTestResult& result_proto, absl::Time started,
                  absl::Time ended) {
  google::protobuf::Timestamp started_proto;
  CHECK_OK(silifuzz::EncodeGoogleApiProto(started, &started_proto));
  *result_proto.mutable_testing_started() = started_proto;

  google::protobuf::Timestamp ended_proto;
  CHECK_OK(silifuzz::EncodeGoogleApiProto(ended, &ended_proto));
  *result_proto.mutable_testing_ended() = ended_proto;
}

int TestMain(std::vector<char*> positional_args) {
  const bool print_proto = absl::GetFlag(FLAGS_print_proto);
  const bool printing_allowed = !print_proto;

  absl::Time test_started = absl::Now();
  if (printing_allowed) {
    std::cout << "Time started: " << test_started << std::endl;
    std::cout << "Start timestamp: " << absl::ToUnixMillis(test_started)
              << std::endl;
    std::cout << std::endl;
  }

  InitXedIfNeeded();

  std::string hostname(ShortHostname());
  std::string version =
      absl::StrCat(kHashTestVersionMajor, ".", kHashTestVersionMinor, ".",
                   kHashTestVersionPatch);

  if (printing_allowed) {
    std::cout << "Host: " << hostname << std::endl;
    std::cout << "Version: " << version << std::endl;
  }

  // Alow the platform to be overridden.
  PlatformId platform = absl::GetFlag(FLAGS_platform);
  if (platform == PlatformId::kUndefined) {
    // Default to the current platform.
    platform = CurrentPlatformId();
  }
  xed_chip_enum_t chip = PlatformIdToChip(platform);

  if (chip == XED_CHIP_INVALID) {
    if (print_proto) {
      proto::HashTestResult result_proto;
      result_proto.set_hostname(hostname);
      result_proto.set_platform(EnumStr(platform));
      result_proto.set_version(version);

      result_proto.set_status(proto::HashTestResult::PLATFORM_NOT_SUPPORTED);

      SetTestTimes(result_proto, test_started, absl::Now());

      result_proto.set_tests_run(0);
      result_proto.set_tests_failed(0);

      result_proto.SerializeToOstream(&std::cout);
    } else {
      std::cout << "Unsupported platform: " << EnumStr(platform);
    }
    return EXIT_FAILURE;
  }

  size_t vector_width = ChipVectorRegisterWidth(chip);
  size_t mask_width = ChipMaskRegisterWidth(chip);

  if (printing_allowed) {
    std::cout << "Platform: " << EnumStr(platform) << std::endl;
    std::cout << "Vector width: " << vector_width << std::endl;
    std::cout << "Mask width: " << mask_width << std::endl;
  }

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

  if (printing_allowed) {
    std::cout << std::endl;
    std::cout << "Tests: " << num_tests << std::endl;
    std::cout << "Batch size: " << batch_size << std::endl;
    std::cout << "Inputs: " << num_inputs << std::endl;
    std::cout << "Repeat: " << num_repeat << std::endl;
    std::cout << "Iterations: " << num_iterations << std::endl;

    // Display seed so that we can recreate this run later, if needed.
    std::cout << std::endl;
    std::cout << "Seed: " << FormatSeed(seed) << std::endl;
  }

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

  size_t cpu_limit = absl::GetFlag(FLAGS_j);
  if (cpu_limit > 0 && cpu_limit < cpu_list.size()) {
    // Run on a random subset of CPUs.
    std::vector<int> sampled;
    std::sample(cpu_list.begin(), cpu_list.end(), std::back_inserter(sampled),
                cpu_limit, rng);
    cpu_list = std::move(sampled);
  }

  if (printing_allowed) {
    std::cout << std::endl;
    std::cout << "Num threads: " << cpu_list.size() << std::endl;
  }
  CHECK_GT(cpu_list.size(), 0);

  // Create a pool of worker threads.
  ParallelWorkerPool workers(cpu_list.size());

  // Bind each worker thread to one of the available CPUs.
  workers.DoWork(cpu_list, [](int cpu) { SetCPUAffinity(cpu); });

  // Generating input entropy can be somewhat expensive, so amortize it across
  // all the tests.
  std::vector<Input> inputs = GenerateInputs(input_rng, num_inputs);

  const CorpusConfig default_corpus_config = {
      .name = "default",
      .tags = {},
      .chip = chip,
      .synthesis_config =
          {
              .ipool = &ipool,
          },
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
              .mxcsr = kMXCSRMaskAll,
          },
  };

  std::vector<CorpusConfig> corpus_config;

  const InstructionPool ipool_no_128 =
      ipool.Filter([](const InstructionCandidate& candidate) {
        return candidate.vector_width != 128;
      });

  // Vary the rounding mode. This doesn't have a large impact on hit rate, but
  // some machines prefer specific modes.
  for (uint32_t rounding_mode : {kMXCSRRoundNearest, kMXCSRRoundDown,
                                 kMXCSRRoundUp, kMXCSRRoundTowardsZero}) {
    // Vary FTZ. Flush to zero generally has a slightly higher hit rate.
    for (bool flush_to_zero : {false, true}) {
      // Vary DAZ. Denormals are zero generally has a slightly higher hit rate.
      for (bool denormals_are_zeros : {false, true}) {
        CorpusConfig base = default_corpus_config;

        uint32_t mxcsr = kMXCSRMaskAll;
        mxcsr |= rounding_mode;
        switch (rounding_mode) {
          case kMXCSRRoundNearest:
            base.tags.push_back("round_nearest");
            break;
          case kMXCSRRoundDown:
            base.tags.push_back("round_down");
            break;
          case kMXCSRRoundUp:
            base.tags.push_back("round_up");
            break;
          case kMXCSRRoundTowardsZero:
            base.tags.push_back("round_towards_zero");
            break;
          default:
            abort();
        };
        if (flush_to_zero) {
          mxcsr |= kMXCSRFlushToZero;
          base.tags.push_back("ftz");
        }
        if (denormals_are_zeros) {
          mxcsr |= kMXCSRDenormalsAreZeros;
          base.tags.push_back("daz");
        }
        base.run_config.mxcsr = mxcsr;

        // Generate different branch configurations.
        // 0 does not test branches.
        // 1 has unpredictable 50/50% branches that slow down execution.
        // Subsequent variants become more and more predictable and run faster
        // because the branches are predicted.
        // 3 seems to generally have the highest hit rate.
        // 4 seems to generally have the lowest hit rate.
        // Different machines respond differently to these configurations,
        // however, so switching between them produces the best result.
        // TODO(ncbray): is it worth eliminating 4?
        for (int branch_test_bits : {0, 1, 2, 3, 4}) {
          CorpusConfig branch_config = base;
          branch_config.synthesis_config.branch_test_bits = branch_test_bits;
          if (branch_test_bits == 0) {
            // Turn off branch generation for the btb0 case.
            branch_config.synthesis_config.min_duplication_rate = 0.0f;
            branch_config.synthesis_config.max_duplication_rate = 0.0f;
          }
          branch_config.tags.push_back(absl::StrCat("btb", branch_test_bits));
          corpus_config.push_back(branch_config);

          // Generate a variant with 128-bit vector instructions filtered out.
          // This reduces instruction coverage, but can greatly speed up test
          // execution on some microarchitectures. Some defective machines do
          // not care about this setting, others have strongly affected hit
          // rates.
          CorpusConfig filtered_corpus_config = branch_config;
          filtered_corpus_config.name = "-vec128";
          filtered_corpus_config.tags.push_back("-vec128");
          filtered_corpus_config.synthesis_config.ipool = &ipool_no_128;
          corpus_config.push_back(filtered_corpus_config);
        }
      }
    }
  }

  // Name the corpus based on the tags.
  for (CorpusConfig& config : corpus_config) {
    config.name = TagsToName(config.tags);
  }

  // Run the experiments in a random order to avoid creating sampling bias when
  // we halt testing at a specific time.
  std::shuffle(corpus_config.begin(), corpus_config.end(), rng);

  // Static so the signal handler callback can access it.
  static ResultReporter result(test_started, printing_allowed);

  absl::Duration testing_time = absl::GetFlag(FLAGS_time);
  absl::Duration corpus_time = absl::GetFlag(FLAGS_corpus_time);

  signal(SIGTERM, [](int) { result.StopRunning(); });
  signal(SIGINT, [](int) { result.StopRunning(); });

  size_t test_index = 0;
  std::vector<CorpusStats> corpus_stats(corpus_config.size());
  size_t current_variant = 0;
  while (true) {
    if (result.ShouldStopRunning()) {
      break;
    }
    absl::Time corpus_started = absl::Now();
    absl::Duration testing_time_remaining =
        testing_time - (corpus_started - test_started);
    if (testing_time_remaining <= absl::ZeroDuration()) {
      break;
    }
    absl::Duration clamped_corpus_time =
        std::min(corpus_time, testing_time_remaining);
    RunTestCorpus(test_index, test_rng, workers, corpus_config[current_variant],
                  corpus_stats[current_variant], clamped_corpus_time, result,
                  printing_allowed);
    test_index += corpus_config[current_variant].num_tests;
    current_variant = (current_variant + 1) % corpus_config.size();
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

  std::vector<uint64_t> suspected_cpus;
  for (const auto& [cpu, _] : hit_counts) {
    suspected_cpus.push_back(cpu);
  }
  std::sort(suspected_cpus.begin(), suspected_cpus.end());

  absl::Time test_ended = absl::Now();

  // Aggregate the stats from each config.
  CorpusStats all_stats{};
  for (size_t i = 0; i < corpus_config.size(); ++i) {
    all_stats += corpus_stats[i];
  }
  const bool failed = all_stats.test_instance_hit > 0;

  if (printing_allowed) {
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

    // Print stats.
    for (size_t i = 0; i < corpus_config.size(); ++i) {
      PrintCorpusStats(corpus_config[i].name, corpus_stats[i],
                       workers.NumWorkers());
    }
    PrintCorpusStats("all", all_stats, workers.NumWorkers());

    std::cout << std::endl;
    std::cout << (test_hit_counts.size() / (double)all_stats.distinct_tests)
              << " per test hit rate" << std::endl;
    std::cout << "Total time: " << (test_ended - test_started) << std::endl;
    std::cout << "Time ended: " << test_ended << std::endl;
    std::cout << "End timestamp: " << absl::ToUnixMillis(test_ended)
              << std::endl;

    // Print machine readable stats.
    std::cout << std::endl;
    std::cout << "BEGIN_JSON" << std::endl;
    JSONFormatter out(std::cout);
    out.Object([&] {
      // Host information.
      out.Field("hostname", hostname);
      out.Field("platform", EnumStr(platform));
      out.Field("vector_width", vector_width);
      out.Field("mask_width", mask_width);

      // Information about this run.
      out.Field("version", version);
      out.Field("seed", seed);
      out.Field("threads", workers.NumWorkers());
      out.Field("test_started", absl::ToUnixMillis(test_started));
      out.Field("test_ended", absl::ToUnixMillis(test_ended));

      out.Field("variants").List([&] {
        for (size_t i = 0; i < corpus_config.size(); ++i) {
          out.Object([&] {
            out.Field("config");
            FormatCorpusConfigJSON(corpus_config[i], out);
            out.Field("stats");
            FormatCorpusStatsJSON(corpus_stats[i], out);
          });
        }
      });

      // TODO(ncbray): aggregate stats when there is more than one.
      out.Field("stats");
      FormatCorpusStatsJSON(all_stats, out);

      out.Field("cpus_hit").List([&] {
        for (uint64_t cpu : suspected_cpus) {
          out.Value(cpu);
        }
      });
    });
    std::cout << std::endl;
    std::cout << "END_JSON" << std::endl;
  }

  if (print_proto) {
    proto::HashTestResult result_proto;
    result_proto.set_hostname(hostname);
    result_proto.set_platform(EnumStr(platform));
    result_proto.set_version(version);

    result_proto.set_status(failed ? proto::HashTestResult::FAILED
                                   : proto::HashTestResult::OK);

    SetTestTimes(result_proto, test_started, test_ended);

    result_proto.set_tests_run(all_stats.test_instance_run);
    result_proto.set_tests_failed(all_stats.test_instance_hit);

    for (uint64_t cpu : cpu_list) {
      result_proto.add_tested_cpus(cpu);
    }
    for (uint64_t cpu : suspected_cpus) {
      result_proto.add_suspected_cpus(cpu);
    }

    result_proto.SerializeToOstream(&std::cout);
  }

  return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}

}  // namespace

}  // namespace silifuzz

int main(int argc, char* argv[]) {
  std::vector<char*> positional_args = absl::ParseCommandLine(argc, argv);
  return silifuzz::TestMain(positional_args);
}
