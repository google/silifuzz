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
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <filesystem>  // NOLINT
#include <fstream>
#include <memory>
#include <string>
#include <system_error>  // NOLINT
#include <vector>

#include "absl/random/random.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "./orchestrator/corpus_util.h"
#include "./util/checks.h"

namespace silifuzz {
namespace fs = std::filesystem;

std::vector<pid_t> ListChildrenPids(pid_t pid) {
  std::vector<pid_t> pids;
  // /proc/$pid/task lists all thread ids of the process. The "children"
  // file then contains PIDs of the child processes spawned by the corresponding
  // thread.
  std::error_code ec;
  auto path = absl::StrCat("/proc/", pid, "/task");
  fs::directory_iterator dir_iter(path, ec);
  if (ec) {
    LOG_ERROR(ec.message(), " ", path);
    return {};
  }
  for (const auto &task : dir_iter) {
    if (task.is_directory()) {
      std::ifstream ifs;
      ifs.open(task.path() / "children");
      // This code ignores all I/O errors since the child processes exit
      // asynchroniously.
      if (!ifs.good()) {
        continue;
      }
      std::string line;
      if (std::getline(ifs, line)) {
        for (const auto pid_s : absl::StrSplit(line, ' ')) {
          pid_t pid = 0;
          if (absl::SimpleAtoi(pid_s, &pid)) {
            pids.push_back(pid);
          }
        }
      }
      ifs.close();
    }
  }
  return pids;
}

// Returns the Statm struct for `pid`. Returns NOT_FOUND if the process does
// not exist.
absl::StatusOr<Statm> ProcessStatm(pid_t pid) {
  static int page_size = getpagesize();
  std::ifstream ifs;
  auto path = absl::StrCat("/proc/", pid, "/statm");
  ifs.open(path);
  if (!ifs.good()) return absl::NotFoundError(path);
  Statm statm = {};
  ifs >> statm.vm_size_bytes >> statm.rss_bytes;
  if (!ifs.good()) return absl::NotFoundError(path);
  ifs.close();
  statm.vm_size_bytes *= page_size;
  statm.rss_bytes *= page_size;
  return statm;
}

uint64_t MaxRunnerRssSizeBytes(pid_t pid, absl::string_view runner_name) {
  std::vector<pid_t> pids = ListChildrenPids(pid);
  uint64_t value = 0;
  for (pid_t child_pid : pids) {
    std::error_code ec;
    fs::path exe =
        fs::read_symlink(absl::StrCat("/proc/", child_pid, "/exe"), ec);
    if (ec || !absl::StrContains(exe.string(), runner_name)) {
      continue;
    }
    if (absl::StatusOr<Statm> s = ProcessStatm(child_pid); s.ok()) {
      value = std::max(value, s->rss_bytes);
    } else {
      // Processes come and go regularly. An error returned from ProcessStatm()
      // doesn't indicate a problem for the purposes of this function and
      // can be skipped.
      VLOG_INFO(2, s.status().message());
    }
  }
  return value;
}

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

absl::StatusOr<std::vector<std::string>> CapShardsToMemLimit(
    const std::vector<std::string> &shards, int64_t memory_usage_limit_mb,
    uint64_t max_cpus) {
  // How much memory a single runner uses. 512Mb works the current corpus but
  // ideally the value should be computed on the fly by either loading a single
  // shard into the runner or precomputing the value and recording it in the
  // metadata file.
  // TODO(ksteuck): Fix
  constexpr uint64_t kSingleRunnerMemoryUsageMb = 512;

  int64_t memory_budget_mb = memory_usage_limit_mb;
  VLOG_INFO(0, "Initial mem budget is ", memory_budget_mb, "MB");
  memory_budget_mb -= kSingleRunnerMemoryUsageMb * max_cpus;
  if (memory_budget_mb <= 0) {
    return absl::ResourceExhaustedError(absl::StrCat(
        "Not enough memory to run ", max_cpus,
        " runners with the given budget of ", memory_usage_limit_mb, "MB"));
  }
  ASSIGN_OR_RETURN_IF_NOT_OK(
      uint64_t top_shard_size_mb, [&]() -> absl::StatusOr<uint64_t> {
        // Probe the top shard size. Works under the assumption that all shards
        // are equally sized.
        ASSIGN_OR_RETURN_IF_NOT_OK(InMemoryCorpora top_shard,
                                   LoadCorpora({shards[0]}));
        off_t top_shard_size =
            lseek64(top_shard.shards[0].file_descriptor.borrow(), 0, SEEK_END);
        if (top_shard_size < 0) {
          return absl::InternalError(absl::StrCat("lseek64 errno = ", errno));
        }
        // Round up to 1 meg.
        return std::max<uint64_t>(1, top_shard_size / (1024 * 1024));
      }());
  int max_shards =
      std::min<int>(shards.size(), memory_budget_mb / top_shard_size_mb);
  if (max_shards <= 0) {
    return absl::ResourceExhaustedError(absl::StrCat(
        "Cannot load any shards given the remaining memory budget ",
        memory_budget_mb, "MB. Shard size = ", top_shard_size_mb, "MB"));
  }

  VLOG_INFO(0, "Shard 0 size is ", top_shard_size_mb,
            "MB. With the remaining budget of ", memory_budget_mb,
            "MB we can fit ", max_shards, " of ", shards.size());
  memory_budget_mb -= top_shard_size_mb * max_shards;
  VLOG_INFO(0, "Total expected memory usage of SiliFuzz is ",
            memory_usage_limit_mb - memory_budget_mb, "MB");
  std::vector<std::string> rv = shards;
  std::shuffle(rv.begin(), rv.end(), absl::BitGen());
  rv.resize(max_shards);
  return rv;
}

}  // namespace silifuzz
