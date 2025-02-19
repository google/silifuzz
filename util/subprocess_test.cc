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

#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>  // NOLINT

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "./util/testing/status_macros.h"
#include "./util/testing/status_matchers.h"

namespace silifuzz {
namespace {
using silifuzz::testing::StatusIs;
using ::testing::HasSubstr;
using ::testing::IsEmpty;

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

}  // namespace

}  // namespace silifuzz
