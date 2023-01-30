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

#include <unistd.h>

#include <cerrno>
#include <filesystem>  // NOLINT
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <system_error>  // NOLINT
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
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
  //
  path = absl::StrCat("/proc/", pid, "/cmdline");
  ifs.open(path);
  if (!ifs.good()) return absl::NotFoundError(path);
  std::string line;
  std::getline(ifs, line);
  ifs.close();
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

}  // namespace silifuzz
