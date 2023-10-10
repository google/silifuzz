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

// Main entry point for Snap runner binary.
//
// SiliFuzz provides two ways to build this into a binary:
//
// 1) BAKED IN MODE (//third_party/silifuzz/runner:runner_main_nolibc).
//  Link with :default_snap_corpus and define kDefaultSnapCorpus to point to
//  the actual Snap corpus. The corpus is usually produced by :snap_generator
// 2) READING MODE (//third_party/silifuzz/runner:reading_runner_main_nolibc).
//  Link with :loading_snap_corpus. Then pass the file name containing a
//  relocatable corpus as a command line argument.
#include <unistd.h>

#include <cstdlib>

#include "absl/base/attributes.h"
#include "third_party/lss/lss/linux_syscall_support.h"
#include "./runner/default_snap_corpus.h"
#include "./runner/runner.h"
#include "./runner/runner_flags.h"
#include "./util/arch.h"
#include "./util/checks.h"
#include "./util/strcat.h"

namespace silifuzz {

namespace {

constexpr const char* RemoveLeadingDirectory(
    const char* file_name ABSL_ATTRIBUTE_LIFETIME_BOUND) {
  size_t str_begin = 0;
  for (size_t str_end = 0; file_name[str_end]; ++str_end) {
    // Look for the last '/' that is not at the end of the string.
    if (file_name[str_end] == '/' && file_name[str_end + 1] != '\0') {
      str_begin = str_end + 1;
    }
  }
  return file_name + str_begin;
}

int Main(int argc, char* argv[]) {
  int flags_end = ParseRunnerFlags(argc, argv);
  if (flags_end == -1) {
    // Parsing failed. The flag parser already output an error message.
    // Just terminate.
    return EXIT_FAILURE;
  }
  if (FLAGS_help) {
    ShowUsage(argv[0]);
    return EXIT_SUCCESS;
  }
  if (flags_end < argc && argv[flags_end][0] == '-') {
    // There's an option that didn't parse.
    LOG_ERROR(StrCat({"Unknown flag ", argv[flags_end]}));
    ShowUsage(argv[0]);
    return EXIT_FAILURE;
  }

  RunnerMainOptions options;
  options.strict = FLAGS_strict;

  const char* corpus_file_name = flags_end < argc ? argv[flags_end] : nullptr;
  options.corpus =
      LoadCorpus(corpus_file_name, options.strict, &options.corpus_fd);
  if (options.corpus == nullptr) {
    LOG_ERROR("No corpus file name was specified");
    return EXIT_FAILURE;
  }
  if (FLAGS_corpus_name) {
    options.corpus_name = FLAGS_corpus_name;
  } else if (corpus_file_name) {
    options.corpus_name = RemoveLeadingDirectory(corpus_file_name);
  } else {
    options.corpus_name = "<builtin>";
  }
  if (++flags_end < argc) {
    LOG_ERROR(StrCat({"Flags must come before corpus ", argv[flags_end]}));
    return EXIT_FAILURE;
  }

  if (options.corpus->snaps.size == 0) {
    // Treat an empty corpus file as valid an exit immediately.
    LOG_INFO("The corpus is empty, exiting");
    return EXIT_SUCCESS;
  }

  if (!options.corpus->IsExpectedArch()) {
    LOG_ERROR("Corpus has architecture ",
              options.corpus->header.architecture_id, " but expected ",
              Host::architecture_id);
    return EXIT_FAILURE;
  }

  options.cpu = FLAGS_cpu;
  options.snap_id = FLAGS_snap_id;
  options.num_iterations = FLAGS_num_iterations;
  options.enable_tracer = FLAGS_enable_tracer;
  // TODO(ksteuck): [impl] Implement this in the runner.
  options.run_time_budget_ms = FLAGS_run_time_budget_ms;
  // getpid(2) never fails.
  options.pid = getpid();
  if (FLAGS_seed == 0) {
    // If seed is unspecified, use PIDxTIME as seed. Use pid so that runners
    // starting around the same time have different seeds.
    struct kernel_timeval tv;
    CHECK_EQ(sys_gettimeofday(&tv, nullptr), 0);
    // Formula sourced from "Random Numbers in Scientific Computing:
    // An Introduction" (https://arxiv.org/pdf/1005.4117.pdf)
    int seed = ((tv.tv_sec * 181) * ((options.pid - 83) * 359)) % 104729;
    options.seed = seed > 0 ? seed : -seed;
  } else {
    options.seed = FLAGS_seed;
  }
  options.batch_size = FLAGS_batch_size;
  options.schedule_size = FLAGS_schedule_size;
  options.sequential_mode = FLAGS_sequential_mode;

  // These cannot be set together.
  if (FLAGS_make && FLAGS_sequential_mode) {
    LOG_FATAL("Cannot set both make and sequential mode");
  }

  return (FLAGS_make              ? MakerMain(options)
          : FLAGS_sequential_mode ? RunnerMainSequential(options)
                                  : RunnerMain(options));
}

}  // namespace
}  // namespace silifuzz

int main(int argc, char* argv[]) { return silifuzz::Main(argc, argv); }
