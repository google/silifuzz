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

#include "./runner/runner_flags.h"

#include <cstddef>
#include <cstdint>

#include "./runner/runner.h"
#include "./util/atoi.h"
#include "./util/checks.h"
#include "./util/cpu_id.h"
#include "./util/flag_matcher.h"

namespace silifuzz {

// See the header for description.
int FLAGS_cpu = silifuzz::kAnyCPUId;
const char* FLAGS_snap_id = nullptr;
int FLAGS_run_time_budget_ms = -1;
int FLAGS_num_iterations = 1000000;
uint64_t FLAGS_seed = 0;
bool FLAGS_help = false;
bool FLAGS_make = false;
bool FLAGS_enable_tracer = false;
size_t FLAGS_batch_size = RunnerMainOptions::kDefaultBatchSize;
size_t FLAGS_schedule_size = RunnerMainOptions::kDefaultScheduleSize;
bool FLAGS_sequential_mode = false;

// Print all flags and exit.
void ShowUsage(const char* program_name) {
  LOG_INFO("Usage: ", program_name, " <flags>... [corpus file]");
  LOG_INFO("  flags");
  LOG_INFO("  --cpu [pinned cpu]\tPin runner to specified CPU.");
  LOG_INFO("  --snap_id snap_id\tSnap ID to run.");
  LOG_INFO(
      "  --run_time_budget_ms [value]\tAmount of CPU time allocated for each "
      "snap execution (milliseconds).");
  LOG_INFO("  --num_iterations [value]\tNumber of snap executions to perform.");
  LOG_INFO(
      "  --seed [seed]\tSpecified a decimal random seed if it is not 0 "
      "(default)");
  LOG_INFO("  --make\tRun in make mode.");
  LOG_INFO("  --enable_tracer\tEnable ptrace cooperation.");
  LOG_INFO("  --batch_size [size]\tSnap execution batch size.");
  LOG_INFO("  --schedule_size [size]\tSnap execution schedule size.");
  LOG_INFO("  --sequential_mode\tRun Snaps sequentially once.");
  LOG_INFO("  --help\tPrint usage information.");
}

int ParseRunnerFlags(int argc, char* argv[]) {
  silifuzz::CommandLineFlagMatcher matcher(argc, argv);
  // TODO(dougkwan): [design] move this logic into matcher. This is getting
  // a bit unwieldy as more and more flags are added.
  while (matcher.optind() < argc) {
    if (matcher.Match("cpu", CommandLineFlagMatcher::kRequiredArgument)) {
      uint64_t cpu;
      if (!silifuzz::DecToU64(matcher.optarg(), &cpu)) {
        LOG_ERROR("Invalid cpu ", matcher.optarg());
        return -1;
      }
      FLAGS_cpu = cpu;
    } else if (matcher.Match("help", CommandLineFlagMatcher::kNoArgument)) {
      FLAGS_help = true;
    } else if (matcher.Match("v", CommandLineFlagMatcher::kRequiredArgument)) {
      // TODO(ksteuck): [as-needed] Add DecToI64 to handle v=-1.
      uint64_t v = 0;
      if (!silifuzz::DecToU64(matcher.optarg(), &v)) {
        LOG_ERROR("Invalid v ", matcher.optarg());
        return -1;
      }
      SetVLogLevel(static_cast<int>(v));
    } else if (matcher.Match("seed",
                             CommandLineFlagMatcher::kRequiredArgument)) {
      if (!silifuzz::DecToU64(matcher.optarg(), &FLAGS_seed)) {
        LOG_ERROR("Invalid seed ", matcher.optarg());
        return -1;
      }
    } else if (matcher.Match("snap_id",
                             CommandLineFlagMatcher::kRequiredArgument)) {
      FLAGS_snap_id = matcher.optarg();
    } else if (matcher.Match("run_time_budget_ms",
                             CommandLineFlagMatcher::kRequiredArgument)) {
      uint64_t run_time_budget_ms;
      if (!DecToU64(matcher.optarg(), &run_time_budget_ms) ||
          run_time_budget_ms == 0) {
        LOG_ERROR("Invalid run_time_budget_ms ", matcher.optarg());
        return -1;
      }
      FLAGS_run_time_budget_ms = run_time_budget_ms;
    } else if (matcher.Match("num_iterations",
                             CommandLineFlagMatcher::kRequiredArgument)) {
      uint64_t num_iterations;
      if (!DecToU64(matcher.optarg(), &num_iterations) || num_iterations == 0) {
        LOG_ERROR("Invalid num_iterations ", matcher.optarg());
        return -1;
      }
      FLAGS_num_iterations = num_iterations;
    } else if (matcher.Match("make", CommandLineFlagMatcher::kNoArgument)) {
      FLAGS_make = true;
    } else if (matcher.Match("enable_tracer",
                             CommandLineFlagMatcher::kNoArgument)) {
      FLAGS_enable_tracer = true;
    } else if (matcher.Match("batch_size",
                             CommandLineFlagMatcher::kRequiredArgument)) {
      uint64_t batch_size;
      if (!DecToU64(matcher.optarg(), &batch_size) || batch_size == 0 ||
          batch_size > RunnerMainOptions::kMaxBatchSize) {
        LOG_ERROR("Invalid batch_size ", matcher.optarg());
        return -1;
      }
      FLAGS_batch_size = batch_size;
    } else if (matcher.Match("schedule_size",
                             CommandLineFlagMatcher::kRequiredArgument)) {
      uint64_t schedule_size;
      if (!DecToU64(matcher.optarg(), &schedule_size) || schedule_size == 0) {
        LOG_ERROR("Invalid schedule_size ", matcher.optarg());
        return -1;
      }
      FLAGS_schedule_size = schedule_size;
    } else if (matcher.Match("sequential_mode",
                             CommandLineFlagMatcher::kNoArgument)) {
      FLAGS_sequential_mode = true;
    } else {
      // Exit loop if argument is not recognized.
      break;
    }
  }

  return matcher.optind();
}

}  // namespace silifuzz
