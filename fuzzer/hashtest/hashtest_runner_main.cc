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
#include <iterator>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <utility>
#include <vector>

#include "google/protobuf/timestamp.pb.h"
#include "absl/algorithm/container.h"
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/check.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "./fuzzer/hashtest/corpus_config.h"
#include "./fuzzer/hashtest/corpus_stats.h"
#include "./fuzzer/hashtest/execution_stopper.h"
#include "./fuzzer/hashtest/hashtest_result.pb.h"
#include "./fuzzer/hashtest/json.h"
#include "./fuzzer/hashtest/mxcsr.h"
#include "./fuzzer/hashtest/parallel_worker_pool.h"
#include "./fuzzer/hashtest/resultsrecorder/human_readable_results_recorder.h"
#include "./fuzzer/hashtest/resultsrecorder/proto_results_recorder.h"
#include "./fuzzer/hashtest/resultsrecorder/results_recorder.h"
#include "./fuzzer/hashtest/runnable_corpus.h"
#include "./fuzzer/hashtest/test_partition.h"
#include "./fuzzer/hashtest/testexecution/execute_corpus.h"
#include "./fuzzer/hashtest/testgeneration/candidate.h"
#include "./fuzzer/hashtest/testgeneration/corpus_generator.h"
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

namespace silifuzz {

namespace {

std::string TagsToName(const std::vector<std::string>& tags) {
  if (tags.empty()) {
    return "default";
  }
  return absl::StrJoin(tags, ":");
}

CorpusStats RunTestCorpus(size_t test_index, ParallelWorkerPool& workers,
                          const CorpusConfig& corpus_config,
                          absl::Duration run_time,
                          CorpusGenerator& corpus_generator,
                          ExecutionStopper& execution_stopper,
                          ResultsRecorder* recorder) {
  // Generate tests corpus.
  recorder->RecordGenerationInformation(corpus_config);
  absl::Time corpus_begin = absl::Now();

  // Allocate the corpus.
  RunnableCorpus corpus = corpus_generator.GenerateCorpusForConfig(
      corpus_config.generation_config, corpus_config.instruction_filter,
      workers);

  recorder->RecordCorpusSize(corpus.MemoryUse());

  absl::Time end_state_begin = absl::Now();
  CorpusStats corpus_stats;
  corpus_stats.code_gen_time = end_state_begin - corpus_begin;

  // Generate test+input end states.
  recorder->RecordStartEndStateGeneration();
  size_t unreconciled_end_states =
      GenerateEndStatesForCorpus(corpus_config.run_config, corpus, workers);
  recorder->RecordNumFailedEndStateReconciliations(unreconciled_end_states);
  recorder->RecordEndStateSize(corpus.end_states.size() *
                               sizeof(corpus.end_states[0]));

  absl::Time test_begin = absl::Now();
  corpus_stats.end_state_gen_time = test_begin - end_state_begin;

  // Run test corpus.
  recorder->RecordStartingTestExecution();
  absl::Duration testing_time = run_time - (test_begin - corpus_begin);
  corpus_stats.per_thread_stats =
      ExecuteCorpus(corpus, corpus_config.run_config, testing_time, test_index,
                    execution_stopper, workers);
  corpus_stats.test_time = absl::Now() - test_begin;
  return corpus_stats;
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
  std::unique_ptr<ResultsRecorder> recorder;
  if (print_proto) {
    recorder = std::make_unique<ProtoResultsRecorder>();
  } else {
    recorder = std::make_unique<HumanReadableResultsRecorder>();
  }

  absl::Time test_started = absl::Now();
  recorder->RecordStartInformation(test_started);

  InitXedIfNeeded();

  std::string hostname(ShortHostname());

  // Alow the platform to be overridden.
  PlatformId platform = absl::GetFlag(FLAGS_platform);
  if (platform == PlatformId::kUndefined) {
    // Default to the current platform.
    platform = CurrentPlatformId();
  }
  recorder->RecordPlatformInfo(hostname, EnumStr(platform));
  xed_chip_enum_t chip = PlatformIdToChip(platform);

  if (chip == XED_CHIP_INVALID) {
    recorder->RecordUnsupportedPlatform();
    recorder->FinalizeRecording();
    return EXIT_FAILURE;
  }

  size_t vector_width = ChipVectorRegisterWidth(chip);
  size_t mask_width = ChipMaskRegisterWidth(chip);

  recorder->RecordChipStats(vector_width, mask_width);

  size_t num_tests = absl::GetFlag(FLAGS_tests);
  size_t num_inputs = absl::GetFlag(FLAGS_inputs);
  size_t num_repeat = absl::GetFlag(FLAGS_repeat);
  size_t num_iterations = absl::GetFlag(FLAGS_iterations);
  size_t batch_size = absl::GetFlag(FLAGS_batch);

  // Either get a fixed seed or generate a random seed.
  std::optional<uint64_t> maybe_seed = absl::GetFlag(FLAGS_seed);
  std::random_device hardware_rng{};
  uint64_t seed = maybe_seed.value_or(GetSeed(hardware_rng));

  recorder->RecordConfigurationInformation(
      num_tests, num_inputs, num_repeat, num_iterations, batch_size, seed,
      absl::GetFlag(FLAGS_time), absl::GetFlag(FLAGS_corpus_time));

  // Create separate test and input RNGs so that we can get predictable
  // sequences, given a fixed seed. If we don't do this, small changes to the
  // program could wildly perturb the tests generated, etc.
  std::mt19937_64 rng(seed);
  std::mt19937_64 test_rng(GetSeed(rng));

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

  recorder->RecordThreadInformation(cpu_list);
  CHECK_GT(cpu_list.size(), 0);

  // Create a pool of worker threads.
  ParallelWorkerPool workers(cpu_list.size());

  // Bind each worker thread to one of the available CPUs.
  workers.DoWork(cpu_list, [](int cpu) { SetCPUAffinity(cpu); });

  const CorpusConfig default_corpus_config = {
      .name = "default",
      .tags = {},
      .generation_config =
          {
              .num_inputs = num_inputs,
              .num_tests = num_tests,
              .chip = chip,
          },
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

  auto filter_128_width = [](const InstructionCandidate& candidate) {
    return candidate.vector_width != 128;
  };

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
          branch_config.generation_config.branch_test_bits = branch_test_bits;
          if (branch_test_bits == 0) {
            // Turn off branch generation for the btb0 case.
            branch_config.generation_config.min_duplication_rate = 0.0f;
            branch_config.generation_config.max_duplication_rate = 0.0f;
          }
          branch_config.tags.push_back(absl::StrCat("btb", branch_test_bits));
          branch_config.generation_config.seed = GetSeed(test_rng);
          corpus_config.push_back(branch_config);

          // Generate a variant with 128-bit vector instructions filtered out.
          // This reduces instruction coverage, but can greatly speed up test
          // execution on some microarchitectures. Some defective machines do
          // not care about this setting, others have strongly affected hit
          // rates.
          CorpusConfig filtered_corpus_config = branch_config;
          filtered_corpus_config.name = "-vec128";
          filtered_corpus_config.tags.push_back("-vec128");
          filtered_corpus_config.instruction_filter = filter_128_width;
          filtered_corpus_config.generation_config.seed = GetSeed(test_rng);
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
  static ExecutionStopper execution_stopper;
  signal(SIGTERM, [](int) { execution_stopper.StopExecution(); });
  signal(SIGINT, [](int) { execution_stopper.StopExecution(); });

  absl::Duration testing_time = absl::GetFlag(FLAGS_time);
  absl::Duration corpus_time = absl::GetFlag(FLAGS_corpus_time);

  size_t test_index = 0;
  std::vector<CorpusStats> corpus_stats_list(corpus_config.size());
  size_t current_variant = 0;
  CorpusGenerator corpus_generator;
  while (true) {
    if (execution_stopper.ShouldStopExecuting()) {
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
    CorpusStats stats_for_run =
        RunTestCorpus(test_index, workers, corpus_config[current_variant],
                      clamped_corpus_time, corpus_generator, execution_stopper,
                      recorder.get());
    corpus_stats_list[current_variant] += stats_for_run;
    recorder->RecordCorpusStats(corpus_config[current_variant], stats_for_run,
                                corpus_started);
    test_index += corpus_config[current_variant].generation_config.num_tests;
    current_variant = (current_variant + 1) % corpus_config.size();
  }

  recorder->RecordFinalStats(corpus_config, corpus_stats_list);
  recorder->FinalizeRecording();

  bool failed = absl::c_any_of(
      corpus_stats_list, [](const CorpusStats& s) { return s.num_hits() > 0; });

  return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}

}  // namespace

}  // namespace silifuzz

int main(int argc, char* argv[]) {
  std::vector<char*> positional_args = absl::ParseCommandLine(argc, argv);
  return silifuzz::TestMain(positional_args);
}
