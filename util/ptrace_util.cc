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

#include "./util/ptrace_util.h"

#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <cerrno>
#include <optional>

#include "./util/checks.h"
#include "./util/itoa.h"
#include "./util/subprocess.h"

namespace silifuzz {

bool WaitpidOrDie(pid_t pid, ProcessInfo* info, int options) {
  pid_t child_pid = wait4(pid, &info->status, options, &info->rusage);
  if (child_pid < 0) {
    if (errno == ECHILD) {
      return false;
    }
    LOG_FATAL("waitpid failed on pid ", pid, " : ", ErrnoStr(errno));
  }
  CHECK_EQ(pid, child_pid);
  return true;
}

bool WaitpidToStop(pid_t pid, std::optional<ProcessInfo>* info) {
  ProcessInfo winfo = {};
  if (!WaitpidOrDie(pid, &winfo, __WALL)) {
    // This can only happen if pid is for a process that our caller
    // is not managing, or if our caller might be doing waitpid() on pid
    // concurrently.
    VLOG_INFO(1, "PID ", pid, " has exited and something collected its status");
    *info = std::nullopt;
    return false;
  }
  *info = winfo;
  if (WIFEXITED(winfo.status) || WIFSIGNALED(winfo.status)) {
    if (WIFEXITED(winfo.status)) {
      VLOG_INFO(2, "PID ", pid, " quit, status = ", WEXITSTATUS(winfo.status));
    } else {
      VLOG_INFO(2, "PID ", pid, " received signal ", WTERMSIG(winfo.status));
    }
    return false;
  }
  if (!WIFSTOPPED(winfo.status)) {
    LOG_FATAL("PID ", pid,
              " had unexpected status from waitpid: ", HexStr(winfo.status));
  }
  return true;
}

}  // namespace silifuzz
