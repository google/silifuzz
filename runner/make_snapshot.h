// Copyright 2024 The SiliFuzz Authors.
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

#ifndef THIRD_PARTY_SILIFUZZ_RUNNER_MAKE_SNAPSHOT_H_
#define THIRD_PARTY_SILIFUZZ_RUNNER_MAKE_SNAPSHOT_H_

#include <string>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "./common/proxy_config.h"
#include "./common/snapshot.h"
#include "./player/trace_options.h"
#include "./util/arch.h"
#include "./util/cpu_id.h"

namespace silifuzz {

struct MakingConfig {
  // Location of the runner binary.
  std::string runner_path;

  // How many rw memory pages Make() can add to repair any occurring
  // page faults
  int max_pages_to_add = 5;

  // How many times Verify() will play each snapshot. Higher values provide
  // more confidence that the snapshot is indeed deterministic. The default
  // value is somewhat arbitrary but it should normally be > 1.
  int num_verify_attempts = 5;

  // Which CPU should be making process be performed on?
  // Be default, the making process will run on any CPU that is available.
  // Typically you do not need to override this parameter unless you are running
  // on a machine with a known bad CPU and need to run the making process on a
  // known good CPU.
  int cpu = kAnyCPUId;

  // If true, enforce fuzzing config. Snapshots with non-conforming
  // mappings are rejected.
  bool enforce_fuzzing_config = true;

  TraceOptions trace;

  // Config for when we are making a real Snapshot that we want to persist.
  static MakingConfig Default();

  // Config for when we are making a snapshot and are willing to cut corners for
  // performance, such as running fewer iterations to verify determinism.
  static MakingConfig Quick();
};

// A high-level interface for making / remaking a Snapshot.
absl::StatusOr<Snapshot> MakeSnapshot(const Snapshot& snapshot,
                                      const MakingConfig& making_config);

// A high-level interface for making a Snapshot from raw instructions.
absl::StatusOr<Snapshot> MakeRawInstructions(
    absl::string_view instructions, const MakingConfig& making_config,
    const FuzzingConfig<Host>& fuzzing_config = DEFAULT_FUZZING_CONFIG<Host>);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_RUNNER_MAKE_SNAPSHOT_H_
