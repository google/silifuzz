// Copyright 2026 The Silifuzz Authors.
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

#include "./fuzzer/hashtest/resultsrecorder/human_readable_results_recorder.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "absl/container/btree_map.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "./fuzzer/hashtest/corpus_config.h"
#include "./fuzzer/hashtest/corpus_stats.h"
#include "./fuzzer/hashtest/entropy.h"
#include "./fuzzer/hashtest/json.h"
#include "./fuzzer/hashtest/run_config.h"
#include "./fuzzer/hashtest/testgeneration/version.h"

namespace silifuzz {

namespace {
size_t ToMB(size_t bytes) { return bytes / (1024 * 1024); }

void PrintCorpusStats(const std::string& name, const CorpusStats& corpus_stats,
                      size_t num_workers) {
  std::cout << std::endl;
  std::cout << "Stats / " << name << std::endl;
  std::cout << corpus_stats.code_gen_time << " generating code" << std::endl;
  std::cout << corpus_stats.end_state_gen_time << " generating end states"
            << std::endl;
  std::cout << corpus_stats.test_time << " testing" << std::endl;
  size_t tests_run = corpus_stats.num_runs();
  size_t tests_hit = corpus_stats.num_hits();

  std::cout << tests_run << " runs" << std::endl;
  std::cout << tests_run /
                   (absl::ToDoubleSeconds(corpus_stats.test_time) * num_workers)
            << " iterations per second per core" << std::endl;
  std::cout << tests_hit << " hits" << std::endl;
  std::cout << (tests_hit / absl::ToDoubleSeconds(corpus_stats.test_time))
            << " per second hit rate" << std::endl;
  std::cout << (tests_hit / (double)tests_run) << " per run hit rate"
            << std::endl;
  std::cout << (1e9 * tests_hit / (double)(tests_run))
            << " per billion iteration hit rate" << std::endl;
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
    out.Field("tests_run", corpus_stats.num_runs());
    out.Field("tests_hit", corpus_stats.num_hits());
  });
}

}  // namespace

void HumanReadableResultsRecorder::RecordStartInformation(
    absl::Time start_time) {
  test_start_time_ = start_time;
  std::cout << "Time started: " << start_time << std::endl;
  std::cout << "Start timestamp: " << absl::ToUnixMillis(start_time)
            << std::endl;
  std::cout << std::endl;
}

void HumanReadableResultsRecorder::RecordPlatformInfo(
    absl::string_view hostname, absl::string_view platform) {
  hostname_ = hostname;
  platform_ = platform;
  std::cout << "Host: " << hostname << std::endl;
  std::cout << "Version: " << GetVersionString() << std::endl;
  std::cout << "Platform: " << platform << std::endl;
}

void HumanReadableResultsRecorder::RecordUnsupportedPlatform() {
  std::cout << "Unsupported platform: " << platform_;
}

void HumanReadableResultsRecorder::RecordChipStats(size_t vector_width,
                                                   size_t mask_width) {
  vector_width_ = vector_width;
  mask_width_ = mask_width;
  std::cout << "Vector width: " << vector_width << std::endl;
  std::cout << "Mask width: " << mask_width << std::endl;
}

void HumanReadableResultsRecorder::RecordConfigurationInformation(
    size_t num_tests, size_t num_inputs, size_t num_repeat,
    size_t num_iterations, size_t batch_size, size_t seed,
    absl::Duration alotted_time, absl::Duration per_corpus_time) {
  seed_ = seed;
  std::cout << std::endl;
  std::cout << "Tests: " << num_tests << std::endl;
  std::cout << "Batch size: " << batch_size << std::endl;
  std::cout << "Inputs: " << num_inputs << std::endl;
  std::cout << "Repeat: " << num_repeat << std::endl;
  std::cout << "Iterations: " << num_iterations << std::endl;

  std::cout << "Time Alotted: " << alotted_time << std::endl;
  std::cout << "Per Corpus Alottment: " << per_corpus_time << std::endl;

  // Display seed so that we can recreate this run later, if needed.
  std::cout << std::endl;
  std::cout << "Seed: " << FormatSeed(seed) << std::endl;
}

void HumanReadableResultsRecorder::RecordThreadInformation(
    absl::Span<const int> cpus) {
  num_threads_ = cpus.size();
  std::cout << std::endl;
  std::cout << "Num threads: " << cpus.size() << std::endl;
}

void HumanReadableResultsRecorder::RecordGenerationInformation(
    const CorpusConfig& config) {
  std::cout << std::endl;
  std::cout << "Generating " << config.num_tests << " tests / " << config.name
            << std::endl;
}

void HumanReadableResultsRecorder::RecordCorpusSize(size_t bytes) {
  std::cout << "Corpus size: " << ToMB(bytes) << " MB" << std::endl;
}

void HumanReadableResultsRecorder::RecordStartEndStateGeneration() {
  std::cout << "Generating end states" << std::endl;
}

void HumanReadableResultsRecorder::RecordEndStateSize(size_t bytes) {
  std::cout << "End state size: " << ToMB(bytes) << " MB" << std::endl;
}

void HumanReadableResultsRecorder::RecordStartingTestExecution() {
  std::cout << "Running tests" << std::endl;
}

void HumanReadableResultsRecorder::RecordNumFailedEndStateReconciliations(
    size_t failed_reconciliations) {
  if (failed_reconciliations > 0) {
    std::cout << "Failed to reconcile " << failed_reconciliations
              << " end states." << std::endl;
  }
}

void HumanReadableResultsRecorder::RecordCorpusStats(
    const CorpusConfig& config, const CorpusStats& stats,
    absl::Time corpus_start_time) {
  std::cout << stats.num_hits() << " hits in "
            << (absl::Now() - corpus_start_time) << std::endl;
}

void HumanReadableResultsRecorder::RecordFinalStats(
    const std::vector<CorpusConfig>& corpus_configs,
    const std::vector<CorpusStats>& corpus_stats) {
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

  // Aggregate the stats for all configs.
  CorpusStats all_stats{};
  for (const auto& corpus_stat : corpus_stats) {
    all_stats += corpus_stat;
    for (const auto& per_thread_kv : corpus_stat.per_thread_stats) {
      for (const auto& hit : per_thread_kv.second.hits) {
        ++test_hit_counts[hit.test_seed];
        ++hit_counts[hit.cpu][hit.test_seed][hit.input_seed];
      }
    }
  }

  std::vector<uint64_t> suspected_cpus;
  for (const auto& [cpu, _] : hit_counts) {
    suspected_cpus.push_back(cpu);
  }
  std::sort(suspected_cpus.begin(), suspected_cpus.end());

  test_end_time_ = absl::Now();

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
  for (size_t i = 0; i < corpus_configs.size(); ++i) {
    if (!corpus_stats[i].per_thread_stats.empty()) {
      PrintCorpusStats(corpus_configs[i].name, corpus_stats[i], num_threads_);
    }
  }
  PrintCorpusStats("all", all_stats, num_threads_);

  size_t total_tests_run = 0;
  for (const auto& [_, thread_stats] : all_stats.per_thread_stats) {
    total_tests_run += thread_stats.tests_run;
  }
  std::cout << std::endl;
  std::cout << (test_hit_counts.size() / (double)total_tests_run)
            << " per test hit rate" << std::endl;
  std::cout << "Total time: " << (test_end_time_ - test_start_time_)
            << std::endl;
  std::cout << "Time ended: " << test_end_time_ << std::endl;
  std::cout << "End timestamp: " << absl::ToUnixMillis(test_end_time_)
            << std::endl;

  // Print machine readable stats.
  if (kPrintJSON) {
    PrintJSON(all_stats, suspected_cpus, corpus_configs, corpus_stats);
  }
}

void HumanReadableResultsRecorder::FinalizeRecording() {}

void HumanReadableResultsRecorder::PrintJSON(
    const CorpusStats& all_stats, const std::vector<uint64_t>& suspected_cpus,
    const std::vector<CorpusConfig>& corpus_configs,
    const std::vector<CorpusStats>& corpus_stats) {
  std::cout << std::endl;

  std::cout << "BEGIN_JSON" << std::endl;
  JSONFormatter out(std::cout);
  out.Object([&] {
    // Host information.
    out.Field("hostname", hostname_);
    out.Field("platform", platform_);
    out.Field("vector_width", vector_width_);
    out.Field("mask_width", mask_width_);

    // Information about this run.
    out.Field("version", GetVersionString());
    out.Field("seed", seed_);
    out.Field("threads", num_threads_);
    out.Field("test_started", absl::ToUnixMillis(test_start_time_));
    out.Field("test_ended", absl::ToUnixMillis(test_end_time_));

    out.Field("variants").List([&] {
      for (size_t i = 0; i < corpus_configs.size(); ++i) {
        if (corpus_stats[i].num_runs() == 0) {
          continue;
        }
        out.Object([&] {
          out.Field("config");
          FormatCorpusConfigJSON(corpus_configs[i], out);
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

}  // namespace silifuzz
