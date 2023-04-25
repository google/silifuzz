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
#include <sys/types.h>

#include <string>
#include <vector>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"

namespace silifuzz {

// Represents the contents of /proc/$/statm file.
struct Statm {
  uint64_t vm_size_bytes;
  uint64_t rss_bytes;
};

// Returns max RSS of the immediate childen of `pid` as reported by the
// corresponding /proc/pid/statm files. The `runner_name` specifies a string
// that the executable path of the process must contain to be considered of
// interest.
uint64_t MaxRunnerRssSizeBytes(
    pid_t pid, absl::string_view runner_name = "reading_runner");

// Returns the `pid`s VmSize as reported by /proc/pid/statm
absl::StatusOr<Statm> ProcessStatm(pid_t pid);

// Returns all child processes of `pid`.
std::vector<pid_t> ListChildrenPids(pid_t pid);

// Returns the "MemAvailable" from /proc/meminfo. According to man 5 proc this
// is "An estimate of how much memory is available for starting new
// applications, without swapping.". Note that the contents of the file is not
// containerized. Any cgroup limits won't be reflected in the result.
absl::StatusOr<uint64_t> AvailableMemoryMb();

// Caps the number of `shards` such that the entire process fits in the
// supplied `memory_usage_limit_mb`. `max_cpus` is the number of runner
// processes that will be run in parallel.
// NOTE: This function relies on the shard size and a guessestimate of how much
// memory (max) a runner can use. The caller may want to apply a fudge factor of
// 0.8 to the limit value to reduce memory pressure.
absl::StatusOr<std::vector<std::string>> CapShardsToMemLimit(
    const std::vector<std::string> &shards, int64_t memory_usage_limit_mb,
    uint64_t max_cpus);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_ORCHESTRATOR_ORCHESTRATOR_UTIL_H_
