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

#include <algorithm>
// simple fix tool that converts raw instruction blobs into a runnable Snap
// corpus.
//
// Usage:
//   simple_fix_tool_main [optional flags] <corpus_0> .. <corpus_n>
//
// To list flags, use simple_fix_tool_main --help.
#include <cstdlib>
#include <string>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/initialize.h"
#include "absl/strings/string_view.h"
#include "./tool_libs/simple_fix_tool_counters.h"
#include "./tools/simple_fix_tool.h"
#include "./util/checks.h"

ABSL_FLAG(std::string, output_path_prefix, "",
          "path prefix for output file shards, e.g. /tmp/corpus.  "
          "A shard index is appended to each output shard file.");
ABSL_FLAG(int, num_output_shards, 1, "number of shards in the output corpus");

ABSL_FLAG(int, num_partitioning_iterations, 10,
          "Number of times the corpus partitioner runs");

ABSL_FLAG(int, parallelism, 0,
          "Number of parallel worker threads.  If it is 0, the simple fix tool "
          "uses the maximum hardware parallelism.");

ABSL_FLAG(bool, x86_filter_split_lock, true,
          "On x86, filter snaps with lock instructions accessing memory across "
          "cache line boundaries.");

ABSL_FLAG(bool, x86_filter_vsyscall_region_access, true,
          "On x86, filter snaps with memory accesses to vsyscall region.");

ABSL_FLAG(bool, filter_memory_access, false,
          "Filter snaps with memory accesses Currently x86-only.");

ABSL_FLAG(bool, enforce_fuzzing_config, true,
          "Filter snaps that do not conform to fuzzing config.");

ABSL_FLAG(bool, x86_filter_non_canonical_evex_sp, true,
          "Filter snaps that contain EVEX instructions that read from stack "
          "pointer, write to AVX registers, and are non-canonical (i.e. x_bar "
          "bit is clear).");

namespace silifuzz {
namespace {

int SimpleFixToolMain(int argc, char* argv[]) {
  auto non_flag_args = absl::ParseCommandLine(argc, argv);
  // Initialize the logging subsystem.
  absl::InitializeLog();

  // All non-flag-args are inputs except args[0], which is the executable name.
  CHECK_GT(non_flag_args.size(), 0);
  const std::vector<std::string> inputs(non_flag_args.begin() + 1,
                                        non_flag_args.end());
  if (inputs.empty()) {
    LOG_ERROR("No input corpus specified");
    return EXIT_FAILURE;
  }

  SimpleFixToolOptions options;
  options.num_partitioning_iterations =
      absl::GetFlag(FLAGS_num_partitioning_iterations);
  options.parallelism = absl::GetFlag(FLAGS_parallelism);
  options.x86_filter_split_lock = absl::GetFlag(FLAGS_x86_filter_split_lock);
  options.x86_filter_vsyscall_region_access =
      absl::GetFlag(FLAGS_x86_filter_vsyscall_region_access);
  options.filter_memory_access = absl::GetFlag(FLAGS_filter_memory_access);
  options.enforce_fuzzing_config = absl::GetFlag(FLAGS_enforce_fuzzing_config);
  options.x86_filter_non_canonical_evex_sp =
      absl::GetFlag(FLAGS_x86_filter_non_canonical_evex_sp);

  fix_tool_internal::SimpleFixToolCounters counters;
  FixupCorpus(options, inputs, absl::GetFlag(FLAGS_output_path_prefix),
              absl::GetFlag(FLAGS_num_output_shards), &counters);

  // Dump counters.
  std::vector<std::string> counter_names = counters.GetCounterNames();
  std::sort(counter_names.begin(), counter_names.end());
  for (const std::string& counter_name : counter_names) {
    LOG_INFO(counter_name, " ", counters.GetValue(counter_name));
  }

  return EXIT_SUCCESS;
}

}  // namespace
}  // namespace silifuzz

int main(int argc, char* argv[]) {
  return silifuzz::SimpleFixToolMain(argc, argv);
}
