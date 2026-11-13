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

#include <signal.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <string>
#include <thread>  // NOLINT

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "./util/testing/status_macros.h"
#include "./util/testing/status_matchers.h"

namespace silifuzz {

class SubprocessPeer {
 public:
  static int child_stdout(const Subprocess& sp) { return sp.child_stdout_; }
};

namespace {
using silifuzz::testing::StatusIs;
using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::Not;
using ::testing::StartsWith;

// The goal of this check is to make sure _some_ sort of reasonable rusage
// information is being returned, no matter how the process behaves.
// This checks the plumbing is connected, essentially.
void ProcessInfoLooksReasonable(const ProcessInfo& info) {
  // The process should have used at least 4kB of memory.
  EXPECT_GE(info.rusage.ru_maxrss, 4);

  // It'a difficult to say what the other values should be.
}

TEST(Subprocess, Communicate) {
  Subprocess sp;
  ASSERT_OK(sp.Start({"/bin/sh", "-c", "echo -n stdout"}));
  std::string stdout;
  ProcessInfo info = sp.Communicate(&stdout);
  EXPECT_EQ(info.status, 0);
  ProcessInfoLooksReasonable(info);
  EXPECT_EQ(stdout, "stdout");
}

TEST(Subprocess, StatusCode) {
  Subprocess sp;
  ASSERT_OK(sp.Start({"/bin/false"}));
  std::string stdout;
  ProcessInfo info = sp.Communicate(&stdout);
  EXPECT_EQ(WEXITSTATUS(info.status), 1);
  ProcessInfoLooksReasonable(info);
}

TEST(Subprocess, StderrDupParent) {
  Subprocess sp;
  ASSERT_OK(sp.Start({"/bin/sh", "-c", "echo -n stderr >&2"}));
  std::string stdout;
  ProcessInfo info = sp.Communicate(&stdout);
  EXPECT_EQ(info.status, 0);
  ProcessInfoLooksReasonable(info);
  EXPECT_EQ(stdout, "");
}

TEST(Subprocess, StderrMapToStdout) {
  Subprocess::Options opts = Subprocess::Options::Default();
  opts.MapStderr(Subprocess::kMapToStdout);
  Subprocess sp(opts);
  ASSERT_OK(sp.Start({"/bin/sh", "-c", "echo -n stderr >&2"}));
  std::string stdout;
  ProcessInfo info = sp.Communicate(&stdout);
  EXPECT_EQ(info.status, 0);
  ProcessInfoLooksReasonable(info);
  EXPECT_EQ(stdout, "stderr");
}

TEST(Subprocess, StderrMapToDevNull) {
  Subprocess::Options opts = Subprocess::Options::Default();
  opts.MapStderr(Subprocess::kMapToDevNull);
  Subprocess sp(opts);
  ASSERT_OK(sp.Start({"/bin/sh", "-c", "echo -n stderr >&2"}));
  std::string stdout;
  // This only tests that setting the mapping does not crash and stdout is
  // empty. There is no easy way to verify that we wrote to /dev/null.
  ProcessInfo info = sp.Communicate(&stdout);
  EXPECT_EQ(info.status, 0);
  ProcessInfoLooksReasonable(info);
  EXPECT_THAT(stdout, IsEmpty());
}

TEST(Subprocess, NoExecutable) {
  Subprocess::Options opts = Subprocess::Options::Default();
  opts.MapStderr(Subprocess::kMapToStdout);
  Subprocess sp(opts);
  ASSERT_THAT(sp.Start({"/bin/foobarbaz"}),
              StatusIs(absl::StatusCode::kInternal,
                       HasSubstr("Binary does not exist")));
}

TEST(Subprocess, DisableAslr) {
  Subprocess::Options opts = Subprocess::Options::Default();
  opts.DisableAslr(true);
  Subprocess sp(opts);
  ASSERT_OK(sp.Start({"/bin/sh", "-c", "grep stack /proc/self/maps"}));
  std::string stdout1;
  ASSERT_EQ(sp.Communicate(&stdout1).status, 0);
  ASSERT_OK(sp.Start({"/bin/sh", "-c", "grep stack /proc/self/maps"}));
  std::string stdout2;
  ASSERT_EQ(sp.Communicate(&stdout2).status, 0);
  ASSERT_EQ(stdout1, stdout2);
}

TEST(Subprocess, ParentDeath) {
  Subprocess::Options opts = Subprocess::Options::Default();
  opts.SetParentDeathSignal(SIGKILL);
  Subprocess sp(opts);
  std::thread t([&] {
    // Start the process in a separate thread. The death signal is delivered
    // when the parent thread exits.
    if (!sp.Start({"/bin/sleep", "3600"}).ok()) {
      abort();
    }
    absl::SleepFor(absl::Seconds(1));
  });
  t.join();
  std::string stdout;
  ProcessInfo info = sp.Communicate(&stdout);
  ASSERT_EQ(WTERMSIG(info.status), SIGKILL);
  ProcessInfoLooksReasonable(info);
}

TEST(Subprocess, SetRLimit) {
  Subprocess::Options opts = Subprocess::Options::Default();
  // 1sec soft limit on CPU  that should trigger a SIGXCPU
  opts.SetRLimit(RLIMIT_CPU, 1, 2);

  Subprocess sp(opts);
  ASSERT_OK(sp.Start({"/bin/sh", "-c", "while :; do :; done"}));
  std::string stdout;
  ProcessInfo info = sp.Communicate(&stdout);
  ASSERT_EQ(WTERMSIG(info.status), SIGXCPU);
  ProcessInfoLooksReasonable(info);
}

TEST(Subprocess, SetITimer) {
  Subprocess::Options opts = Subprocess::Options::Default();
  // 1sec wall clock limit on that should trigger a SIGALRM
  opts.SetITimer(ITIMER_REAL, absl::Seconds(1));

  Subprocess sp(opts);
  ASSERT_OK(sp.Start({"/bin/sh", "-c", "while :; do :; done"}));
  std::string stdout;
  ProcessInfo info = sp.Communicate(&stdout);
  ASSERT_EQ(WTERMSIG(info.status), SIGALRM);
  ProcessInfoLooksReasonable(info);
}

TEST(Subprocess, NoPipeFdLeakAcrossSubprocesses) {
  Subprocess::Options sleep_opts = Subprocess::Options::Default();
  sleep_opts.SetParentDeathSignal(SIGKILL);
  Subprocess sp1(sleep_opts);
  ASSERT_OK(sp1.Start({"/bin/sleep", "3600"}));

  // Read the kernel pipe symlink target ("pipe:[<ino>]") of sp1.child_stdout_
  // directly from the parent's /proc/self/fd table, then scan all open FDs
  // (/proc/self/fd/*) in sp2 to confirm FD_CLOEXEC closed it on execv()
  // without flaking on unrelated background-thread FDs.
  char link_buf[64] = {0};
  std::string sp1_stdout_path =
      absl::StrCat("/proc/self/fd/", SubprocessPeer::child_stdout(sp1));
  ssize_t link_len =
      readlink(sp1_stdout_path.c_str(), link_buf, sizeof(link_buf) - 1);
  EXPECT_GT(link_len, 0);
  if (link_len > 0) {
    std::string sp1_pipe_target(link_buf, link_len);
    EXPECT_THAT(sp1_pipe_target, StartsWith("pipe:["));

    Subprocess sp2;
    absl::Status sp2_status = sp2.Start(
        {"/bin/sh", "-c", "readlink /proc/self/fd/* 2>/dev/null; true"});
    EXPECT_OK(sp2_status);
    if (sp2_status.ok()) {
      std::string sp2_fd_targets;
      EXPECT_EQ(sp2.Communicate(&sp2_fd_targets).status, 0);
      EXPECT_THAT(sp2_fd_targets, HasSubstr("pipe:["));
      EXPECT_THAT(sp2_fd_targets, Not(HasSubstr(sp1_pipe_target)));
    }
  }

  EXPECT_EQ(kill(sp1.pid(), SIGKILL), 0);
  std::string sp1_stdout;
  ProcessInfo info = sp1.Communicate(&sp1_stdout);
  EXPECT_EQ(WTERMSIG(info.status), SIGKILL);
}

}  // namespace

}  // namespace silifuzz
