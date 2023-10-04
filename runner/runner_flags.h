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

#ifndef THIRD_PARTY_SILIFUZZ_RUNNER_RUNNER_FLAGS_H_
#define THIRD_PARTY_SILIFUZZ_RUNNER_RUNNER_FLAGS_H_

#include <cstdint>

//
// Runner command line flags
//

namespace silifuzz {

// CPU on which the runner is pine. kAnyCPUId means not pinned.
extern int FLAGS_cpu;

// Printiple name of the corpus. If null, the corpus name should be derived
// from the corpus path.
extern const char* FLAGS_corpus_name;

// If set, run just this one snap. When null, runs the entire corpus.
extern const char* FLAGS_snap_id;

// Amount of CPU that snapshot's execution is allowed to spend before
// we consider it a runaway. -1 means unlimited.
extern int FLAGS_run_time_budget_ms;

// Number of main loop iterations, in each of which a Snap from the corpus is
// picked an executed.
extern int FLAGS_num_iterations;

// A decimal number used to seed the RNG. 0 means unspecified.
extern uint64_t FLAGS_seed;

// Print usage information and terminate.
extern bool FLAGS_help;

// Run in make mode. In this mode the first snap of the corpus is executed
// exactly once and the actual state of the execution is always written to
// the standard output.
extern bool FLAGS_make;

// Enable ptrace cooperation. Sends SIGSTOP to self before and after each snap
// execution.
extern bool FLAGS_enable_tracer;

// See runner.h for details about batch and schedule sizes.
// Snap execution batch size.
extern uint64_t FLAGS_batch_size;

// Snap execution schedule size.
extern uint64_t FLAGS_schedule_size;

// If true, execute Snaps sequentially once.
extern bool FLAGS_sequential_mode;

// If true, end state is not checked after snap execution.
extern bool FLAGS_skip_end_state_check;

// Parses command line flags of runner and sets flags accordingly. 'argv[]' is
// an array of 'argc' command line argument passed to main(). Parsing starts
// at 'argv[1]' and stops at the first non-flag argument or end of 'argv[]'.
// Return the argument index when parsing stops or -1 if there is any error.
int ParseRunnerFlags(int argc, char* argv[]);

// Prints all flags and exits programe. 'program_name' is the name of the
// program, i.e. argv[0] in main.
void ShowUsage(const char* program_name);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_RUNNER_RUNNER_FLAGS_H_
