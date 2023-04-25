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

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <syscall.h>

#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <optional>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./util/checks.h"
#include "./util/data_dependency.h"
#include "./util/subprocess.h"

namespace silifuzz {
namespace {

using ::testing::Optional;

std::unique_ptr<Subprocess> StartHelperProcess(absl::string_view mode) {
  std::string helper =
      GetDataDependencyFilepath("common/harness_tracer_test_helper");
  Subprocess::Options options = Subprocess::Options::Default();
  options.MapStderr(Subprocess::kMapToStdout);
  auto helper_process = std::make_unique<Subprocess>(options);

  CHECK_OK(helper_process->Start({helper, std::string(mode)}));
  return helper_process;
}

TEST(HarnessTracerTest, CrashAndExit) {
  for (absl::string_view test_mode : {"test-crash", "test-exit"}) {
    SCOPED_TRACE(absl::StrCat("Testing ", test_mode));
    std::unique_ptr<Subprocess> helper_process = StartHelperProcess(test_mode);

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
      EXPECT_EQ(WTERMSIG(*status), SIGABRT);
    } else {
      EXPECT_EQ(*status, 0);
    }
    std::string stdout_str;
    helper_process->Communicate(&stdout_str);
    LOG_INFO("Helper stdout for ", test_mode, ":\n", stdout_str);
  }
}

TEST(HarnessTracerTest, SingleStep) {
  std::unique_ptr<Subprocess> helper_process =
      StartHelperProcess("test-singlestep");

  int n_loop_head_seen = 0;
  HarnessTracer tracer(
      helper_process->pid(), HarnessTracer::kSingleStep,
      [&n_loop_head_seen](pid_t pid, const struct user_regs_struct& regs,
                          HarnessTracer::CallbackReason reason) {
        uint64_t data =
            ptrace(PTRACE_PEEKTEXT, pid, GetInstructionPointer(regs), nullptr);
        CHECK_EQ(errno, 0);
    // PEEKTEXT reads a word from the tracee. x86 is little-endian so bytes
    // are in reverse order
    // The n_loop_head_seen counts the number of time a particular
    // instruction instructions inside the loop in DoWork() in
    // harness_tracer_test_helper.cc is executed
#if defined(__x86_64__)
        // 48 87 db     xchg   rbx,rbx
        const uint32_t kLoopHeadInstruction = 0xdb8748;
        const uint64_t kLoopHeadMask = 0xffffff;
#elif defined(__aarch64__)
        // f100054a        subs    x10, x10, #0x1
        const uint32_t kLoopHeadInstruction = 0xf100054a;
        const uint64_t kLoopHeadMask = 0xffffffff;
#else
#error "Unsupported architecture"
#endif
        if ((data & kLoopHeadMask) == kLoopHeadInstruction) {
          ++n_loop_head_seen;
        }
        return HarnessTracer::kKeepTracing;
      });
  tracer.Attach();
  EXPECT_THAT(tracer.Join(), Optional(0));
  std::string stdout_str;
  helper_process->Communicate(&stdout_str);
  LOG_INFO("Helper stdout:\n", stdout_str);
  // Expecting exactly 100 (50+50) loops executed while the tracer is active.
  EXPECT_EQ(n_loop_head_seen, 100);
}

TEST(HarnessTracerTest, Syscall) {
  std::unique_ptr<Subprocess> helper_process =
      StartHelperProcess("test-syscall");

  // Number of times SYS_getcpu was invoked by SyscallHelper in
  // harness_tracer_test_helper.cc. For every invocation the callback runs twice
  // so this double-counts.
  int num_seen_getcpu = 0;
  HarnessTracer tracer(
      helper_process->pid(), HarnessTracer::kSyscall,
      [&num_seen_getcpu](pid_t pid, const struct user_regs_struct& regs,
                         HarnessTracer::CallbackReason reason) {
        if (GetSyscallNumber(regs) == SYS_getcpu) {
          ++num_seen_getcpu;
        }
        return HarnessTracer::kKeepTracing;
      });
  tracer.Attach();
  EXPECT_THAT(tracer.Join(), Optional(0));
  std::string stdout_str;
  helper_process->Communicate(&stdout_str);
  LOG_INFO("Helper stdout:\n", stdout_str);
  EXPECT_EQ(num_seen_getcpu, 2);
}

TEST(HarnessTracerTest, Signal) {
#if defined(__aarch64__)
  // TODO(ncbray): enable when sys_sigaction works on aarch64.
  GTEST_SKIP() << "Test requires fully functional sys_sigaction.";
#endif
  for (auto mode : {HarnessTracer::kSyscall, HarnessTracer::kSingleStep}) {
    std::unique_ptr<Subprocess> helper_process =
        StartHelperProcess("test-signal");

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
    std::string stdout_str;
    helper_process->Communicate(&stdout_str);
    LOG_INFO("Helper stdout for mode=", mode, ":\n", stdout_str);
  }
}

TEST(HarnessTracerTest, SignalInjection) {
#if defined(__aarch64__)
  // TODO(ncbray): enable when sys_sigaction works on aarch64.
  GTEST_SKIP() << "Test requires fully functional sys_sigaction.";
#endif

  std::unique_ptr<Subprocess> helper_process =
      StartHelperProcess("test-signal-injection");

  HarnessTracer tracer(helper_process->pid(), HarnessTracer::kSyscall,
                       [](pid_t pid, const struct user_regs_struct& regs,
                          HarnessTracer::CallbackReason reason) {
                         if (GetSyscallNumber(regs) == SYS_getcpu) {
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
  std::string stdout_str;
  helper_process->Communicate(&stdout_str);
  LOG_INFO("Helper stdout:\n", stdout_str);
}

}  // namespace

}  // namespace silifuzz
