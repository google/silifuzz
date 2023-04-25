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

#include "./util/subprocess.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/personality.h>
#include <sys/prctl.h>  // prctl(), PR_SET_PDEATHSIG
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "absl/base/attributes.h"
#include "absl/base/call_once.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "./util/checks.h"
#include "./util/itoa.h"
#include "./util/signals.h"

namespace silifuzz {

namespace {
ABSL_CONST_INIT absl::once_flag global_init_once_;
}  // namespace

Subprocess::Subprocess(const Options& options)
    : child_pid_(-1), child_stdout_(-1), options_(options) {
  absl::call_once(global_init_once_, GlobalInit);
}

Subprocess::~Subprocess() {
  if (child_stdout_ != -1) {
    close(child_stdout_);
  }
}

absl::Status Subprocess::Start(const std::vector<std::string>& argv) {
  VLOG_INFO(1, "Running ", absl::StrJoin(argv, " "));
  // Note that we assume that there are no other threads, thus we don't have to
  // do crazy stuff like using socket pairs or avoiding libc locks.

  // [0] is read end, [1] is write end.
  int stdout_pipe[2] = {-1, -1};
  CHECK_NE(pipe(stdout_pipe), -1);

  auto argv_exec = std::make_unique<const char*[]>(argv.size() + 1);
  for (int argc = 0; argc < argv.size(); ++argc) {
    argv_exec[argc] = argv[argc].c_str();
  }
  argv_exec[argv.size()] = nullptr;
  child_pid_ = vfork();
  if (child_pid_ == -1) {
    return absl::InternalError(absl::StrCat("vfork: ", strerror(errno)));
  }

  if (child_pid_ == 0) {
    // We are the child.
    for (const auto& r : options_.rlimit_tuples_) {
      struct rlimit lim = {r.soft_limit, r.hard_limit};
      CHECK_EQ(setrlimit(r.resource, &lim), 0);
    }
    for (const auto& i : options_.itimer_vals_) {
      CHECK_EQ(setitimer(i.which, &i.value, nullptr), 0);
    }
    if (options_.disable_aslr_) {
      int current_persona = personality(0xffffffff);
      if (personality(current_persona | ADDR_NO_RANDOMIZE) == -1) {
        ASS_LOG_FATAL("personality errno =  ", ErrnoStr(errno));
      }
    }
    if (options_.parent_death_signal_ > 0) {
      CHECK_EQ(prctl(PR_SET_PDEATHSIG, options_.parent_death_signal_), 0);
    }
    dup2(stdout_pipe[1], STDOUT_FILENO);
    switch (options_.map_stderr_) {
      case kNoMapping:
        // Same stderr as the parent.
        break;
      case kMapToStdout:
        dup2(stdout_pipe[1], STDERR_FILENO);
        break;
      case kMapToDevNull: {
        int dev_null = open("/dev/null", O_RDWR | O_APPEND);
        CHECK_NE(dev_null, -1);
        CHECK_GE(dup2(dev_null, STDERR_FILENO), 0);
        close(dev_null);
        break;
      }
    }

    close(stdout_pipe[0]);
    close(stdout_pipe[1]);

    execv(argv_exec[0], const_cast<char**>(argv_exec.get()));
    // Can only reach here if exec didn't succeed.

    // Write directly to STDERR_FILENO to avoid stdio code paths that may do
    // stuff that is unsafe here.
    write(STDERR_FILENO, argv_exec[0], strlen(argv_exec[0]));
    const char* message =
        ": program not found or is not executable\n"
        "Please specify a program using absolute path.\n";
    write(STDERR_FILENO, message, strlen(message));

    // Must use _exit() rather than exit() to avoid flushing output buffers
    // that will also be flushed by the parent.
    _exit(1);
    __builtin_unreachable();
  } else {
    // Parent
    close(stdout_pipe[1]);
    child_stdout_ = stdout_pipe[0];
    return absl::OkStatus();
  }
}

int Subprocess::Communicate(std::string* stdout_output) {
  if (child_pid_ == -1 || child_stdout_ == -1) {
    LOG_FATAL("Must call Start() first.");
  }

  while (true) {
    char buffer[4096] = {0};
    int n = read(child_stdout_, buffer, sizeof(buffer));
    if (n == 0) {
      // We've reached a EOF.
      break;
    }
    if (n > 0) {
      stdout_output->append(buffer, n);
    } else {
      if (errno == EINTR) {
        continue;
      }
      LOG_FATAL("read: ", strerror(errno));
    }
  }
  close(child_stdout_);
  child_stdout_ = -1;

  int status = 0;
  while (waitpid(child_pid_, &status, 0) == -1) {
    if (errno == EINTR) {
      continue;
    }
    if (errno == ECHILD) {
      // Someone else snagged the status before we could
      break;
    } else {
      LOG_FATAL("waitpid: ", strerror(errno));
    }
  }

  child_pid_ = -1;
  return status;
}

void Subprocess::GlobalInit() {
  // Make sure SIGPIPE is disabled so that if the child dies it doesn't kill us.
  IgnoreSignal(SIGPIPE);
}

}  // namespace silifuzz
