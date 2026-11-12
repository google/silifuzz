// Copyright 2023 The SiliFuzz Authors.
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

#ifndef THIRD_PARTY_SILIFUZZ_ORCHESTRATOR_ORCHESTRATOR_UTIL_H_
#define THIRD_PARTY_SILIFUZZ_ORCHESTRATOR_ORCHESTRATOR_UTIL_H_

#include <stdint.h>

#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"

namespace silifuzz {

// Represents the resources with which the orchestrator will run.
struct OrchestratorResources {
  uint64_t num_concurrent_runners;
  std::vector<std::string> shards;
};

// Returns the "MemAvailable" from /proc/meminfo. According to man 5 proc this
// is "An estimate of how much memory is available for starting new
// applications, without swapping.". Note that the contents of the file is not
// containerized. Any cgroup limits won't be reflected in the result.
absl::StatusOr<uint64_t> AvailableMemoryMb();

// Caps the `resources` (number of shards and concurrent jobs) such that the
// entire process fits in the supplied `memory_usage_limit_mb`. The capped
// `resources` will be returned and modified in place. NOTE: This function
// relies on the shard size and a guesstimate of how much memory (max) a runner
// can use. The caller may want to apply a fudge factor of 0.8 to the limit
// value to reduce memory pressure.
absl::Status CapResourcesToMemLimit(
    int64_t memory_usage_limit_mb,
    OrchestratorResources& resources /* input/output */);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_ORCHESTRATOR_ORCHESTRATOR_UTIL_H_
