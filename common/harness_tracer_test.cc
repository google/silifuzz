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

#include "./common/harness_tracer.h"

#include <errno.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <syscall.h>

#include <cstdlib>
#include <memory>
#include <optional>
#include <string>

#include "devtools/build/runtime/get_runfiles_dir.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./util/checks.h"
#include "util/process/subprocess.h"

namespace silifuzz {
namespace {

using ::testing::Optional;

std::unique_ptr<SubProcess> HelperProcess(absl::string_view mode) {
  std::string helper = absl::StrCat(
      devtools_build::GetRunfilesDir(),
      "/google3/third_party/silifuzz/common/harness_tracer_test_helper");
  auto helper_process = std::make_unique<SubProcess>();

  helper_process->SetProgram(helper, {std::string(mode)});
  helper_process->SetChannelAction(CHAN_STDIN, ACTION_CLOSE);
  helper_process->SetChannelAction(CHAN_STDOUT, ACTION_DUPPARENT);
  helper_process->SetChannelAction(CHAN_STDERR, ACTION_DUPPARENT);
  return helper_process;
}

TEST(HarnessTracerTest, CrashAndExit) {
  for (absl::string_view test_mode : {"test-crash", "test-exit"}) {
    SCOPED_TRACE(absl::StrCat("Testing ", test_mode));
    std::unique_ptr<SubProcess> helper_process = HelperProcess(test_mode);

    helper_process->Start();

    HarnessTracer tracer(helper_process->pid(), HarnessTracer::kSyscall,
                         [](pid_t pid, const user_regs_struct& regs,
                            HarnessTracer::CallbackReason reason) {
                           return HarnessTracer::kKeepTracing;
                         });
    tracer.Attach();
    std::optional<int> status = tracer.Join();
    ASSERT_TRUE(status.has_value());
    if (test_mode == "test-crash") {
      EXPECT_TRUE(WIFSIGNALED(*status));
      EXPECT_EQ(WTERMSIG(*status), SIGILL);
    } else {
      EXPECT_EQ(*status, 0);
    }
    helper_process->Wait();
  }
}

TEST(HarnessTracerTest, SingleStep) {
  std::unique_ptr<SubProcess> helper_process = HelperProcess("test-singlestep");

  helper_process->Start();

  int n_xchg_seen = 0;
  HarnessTracer tracer(
      helper_process->pid(), HarnessTracer::kSingleStep,
      [&n_xchg_seen](pid_t pid, const struct user_regs_struct& regs,
                     HarnessTracer::CallbackReason reason) {
        uint64_t data = ptrace(PTRACE_PEEKTEXT, pid, regs.rip, nullptr);
        CHECK_EQ(errno, 0);
        // PEEKTEXT reads a word from the tracee. x86 is little-endian so bytes
        // are in reverse order
        // 48 87 db     xchg   rbx,rbx
        // The n_xchg_seen counts the number of time a particular xchg
        // instructions inside the loop in DoWork() in
        // harness_tracer_test_helper.cc is executed
        if ((data & 0xFFFFFF) == 0xDB8748) {
          ++n_xchg_seen;
        }
        return HarnessTracer::kKeepTracing;
      });
  tracer.Attach();
  EXPECT_THAT(tracer.Join(), Optional(0));
  helper_process->Wait();
  // Expecting exactly 100 (50+50) xchg ops executed while the tracer is active.
  EXPECT_EQ(n_xchg_seen, 100);
}

TEST(HarnessTracerTest, Syscall) {
  std::unique_ptr<SubProcess> helper_process = HelperProcess("test-syscall");

  helper_process->Start();

  // Number of times SYS_getcpu was invoked by SyscallHelper in
  // harness_tracer_test_helper.cc. For every invocation the callback runs twice
  // so this double-counts.
  int num_seen_getcpu = 0;
  HarnessTracer tracer(
      helper_process->pid(), HarnessTracer::kSyscall,
      [&num_seen_getcpu](pid_t pid, const struct user_regs_struct& regs,
                         HarnessTracer::CallbackReason reason) {
        // regs.orig_rax is the syscall number. The whole reason this is used
        // instead of regs.rax is because some syscalls clobber rax but orig_rax
        // preserves the value.
        if (regs.orig_rax == SYS_getcpu) {
          ++num_seen_getcpu;
        }
        return HarnessTracer::kKeepTracing;
      });
  tracer.Attach();
  EXPECT_THAT(tracer.Join(), Optional(0));
  helper_process->Wait();
  EXPECT_EQ(num_seen_getcpu, 2);
}

TEST(HarnessTracerTest, Signal) {
  for (auto mode : {HarnessTracer::kSyscall, HarnessTracer::kSingleStep}) {
    std::unique_ptr<SubProcess> helper_process = HelperProcess("test-signal");

    helper_process->Start();

    HarnessTracer tracer(helper_process->pid(), mode,
                         [&](pid_t pid, const struct user_regs_struct& regs,
                             HarnessTracer::CallbackReason reason) {
                           return HarnessTracer::kKeepTracing;
                         });
    tracer.Attach();
    std::optional<int> status = tracer.Join();

    ASSERT_TRUE(status.has_value());
    ASSERT_TRUE(WIFEXITED(*status)) << "status = " << *status;
    if (mode == HarnessTracer::kSyscall) {
      EXPECT_EQ(WEXITSTATUS(*status), 12)
          << "SignalHelper() does 3 rounds of 4 types of causing SIGTRAP";
    } else {
      EXPECT_EQ(WEXITSTATUS(*status), 11)
          << "SignalHelper() does 3 rounds of 4 types of causing SIGTRAP"
          << " except icebp is not properly handled by the tracer";
    }
    helper_process->Wait();
  }
}

TEST(HarnessTracerTest, SignalInjection) {
  std::unique_ptr<SubProcess> helper_process =
      HelperProcess("test-signal-injection");

  helper_process->Start();

  HarnessTracer tracer(helper_process->pid(), HarnessTracer::kSyscall,
                       [](pid_t pid, const struct user_regs_struct& regs,
                          HarnessTracer::CallbackReason reason) {
                         if (regs.orig_rax == SYS_getcpu) {
                           // asks the tracer to inject SIGUSR1 when it sees
                           // getcpu syscall
                           return HarnessTracer::kInjectSigusr1;
                         } else {
                           return HarnessTracer::kKeepTracing;
                         }
                       });
  tracer.Attach();
  std::optional<int> status = tracer.Join();
  ASSERT_TRUE(status.has_value());
  ASSERT_TRUE(WIFEXITED(*status)) << "status = " << *status;
  EXPECT_EQ(WEXITSTATUS(*status), 1);
  helper_process->Wait();
}

}  // namespace

}  // namespace silifuzz
