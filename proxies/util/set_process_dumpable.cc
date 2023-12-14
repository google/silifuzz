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
#include "./proxies/util/set_process_dumpable.h"

#include <sys/prctl.h>
#include <sys/resource.h>

#include <cerrno>

#include "absl/status/status.h"

namespace silifuzz::proxies {

absl::Status SetProcessDumpable() {
  if (prctl(PR_SET_DUMPABLE, 1 /* SUID_DUMP_USER */) != 0) {
    return absl::ErrnoToStatus(errno, "prctl(PR_SET_DUMPABLE) failed");
  }
  struct rlimit core_rlimit {
    .rlim_cur = 0, .rlim_max = 0,
  };
  if (setrlimit(RLIMIT_CORE, &core_rlimit) != 0) {
    return absl::ErrnoToStatus(errno, "setrlimit(RLIMIT_CORE) failed");
  }
  return absl::OkStatus();
}

}  // namespace silifuzz::proxies
