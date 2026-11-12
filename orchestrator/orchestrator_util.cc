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

#include "./orchestrator/orchestrator_util.h"

#include <stdint.h>

#include <algorithm>
#include <cstddef>
#include <fstream>
#include <string>
#include <vector>

#include "absl/random/random.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "./orchestrator/corpus_util.h"
#include "./util/checks.h"

namespace silifuzz {

absl::StatusOr<uint64_t> AvailableMemoryMb() {
  std::ifstream ifs{"/proc/meminfo"};
  if (!ifs.good()) {
    return absl::NotFoundError("/proc/meminfo not found");
  }
  std::string line;
  while (std::getline(ifs, line)) {
    VLOG_INFO(2, line);
    std::vector<std::string> parts =
        absl::StrSplit(line, absl::ByAnyChar(" \t:"), absl::SkipEmpty());
    if (parts.size() != 3) {
      continue;
    }
    if (parts[0] == "MemAvailable") {
      uint64_t mem_available_kb;
      if (!absl::SimpleAtoi(parts[1], &mem_available_kb) || parts[2] != "kB") {
        return absl::InternalError(absl::StrCat("Unexpected entry ", line));
      }
      return mem_available_kb / 1024;
    }
  }
  return absl::NotFoundError("No MemAvailable entry in /proc/meminfo");
}

absl::Status CapResourcesToMemLimit(int64_t memory_usage_limit_mb,
                                    OrchestratorResources& resources) {
  // How much memory a single runner uses. 512Mb works the current corpus but
  // ideally the value should be computed on the fly by either loading a single
  // shard into the runner or precomputing the value and recording it in the
  // metadata file.
  // TODO(ksteuck): Fix
  constexpr uint64_t kSingleRunnerMemoryUsageMb = 512;

  int64_t memory_budget_mb = memory_usage_limit_mb;
  VLOG_INFO(0, "Initial mem budget is ", memory_budget_mb, "MB");
  // Largest shard size is estimated by loading the largest compressed shard
  // file into memory. This is fine in most cases unless some corpus has very
  // low entropy and is compressed very well.
  ASSIGN_OR_RETURN_IF_NOT_OK(const uint64_t shard_size_estimate_mb,
                             EstimateLargestCorpusSizeMB(resources.shards));

  const uint64_t max_num_runners = resources.num_concurrent_runners;
  memory_budget_mb -=
      shard_size_estimate_mb;  // Reserve memory for at least one shard.
  if (memory_budget_mb <= 0) {
    return absl::ResourceExhaustedError(absl::StrCat(
        "Not enough memory to run a single runner with the given budget of ",
        memory_usage_limit_mb, "MB"));
  }
  resources.num_concurrent_runners = std::min<uint64_t>(
      max_num_runners, memory_budget_mb / kSingleRunnerMemoryUsageMb);
  if (resources.num_concurrent_runners == 0) {
    return absl::ResourceExhaustedError(absl::StrCat(
        "Not enough memory to run ", resources.num_concurrent_runners,
        " runners with the given budget of ", memory_usage_limit_mb, "MB"));
  }
  memory_budget_mb -=
      kSingleRunnerMemoryUsageMb * resources.num_concurrent_runners;
  VLOG_INFO(0, "We can schedule ", resources.num_concurrent_runners, "/",
            max_num_runners, " runners of ", kSingleRunnerMemoryUsageMb,
            "MB each with at least one shard of ", shard_size_estimate_mb,
            "MB");

  const size_t total_shards = resources.shards.size();
  memory_budget_mb +=
      shard_size_estimate_mb;  // Add the reserved memory budget back.
  int max_shards =
      std::min<int>(total_shards, memory_budget_mb / shard_size_estimate_mb);
  CHECK_GT(max_shards, 0);
  VLOG_INFO(0, "Largest shard size is ", shard_size_estimate_mb,
            "MB. With the remaining budget of ", memory_budget_mb,
            "MB we can fit ", max_shards, " of ", total_shards);
  memory_budget_mb -= shard_size_estimate_mb * max_shards;
  VLOG_INFO(0, "Total expected memory usage of SiliFuzz is ",
            memory_usage_limit_mb - memory_budget_mb, "MB");
  std::shuffle(resources.shards.begin(), resources.shards.end(),
               absl::BitGen());
  resources.shards.resize(max_shards);
  return absl::OkStatus();
}

}  // namespace silifuzz
