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
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./util/checks.h"
#include "./util/data_dependency.h"
#include "./util/subprocess.h"
#include "./util/user_regs_util.h"

namespace silifuzz {
namespace {

using ::testing::TestWithParam;

// The goal of this check is to make sure _some_ sort of reasonable rusage
// information is being returned, no matter how the process behaves.
// This checks the plumbing is connected, essentially.
void ProcessInfoLooksReasonable(const ProcessInfo& info) {
  // The process should have used at least 4kB of memory.
  EXPECT_GE(info.rusage.ru_maxrss, 4);

  // It'a difficult to say what the other values should be.
}

std::unique_ptr<Subprocess> StartHelperProcess(absl::string_view mode) {
  std::string helper =
      GetDataDependencyFilepath("common/harness_tracer_test_helper");
  Subprocess::Options options = Subprocess::Options::Default();
  options.MapStderr(Subprocess::kMapToStdout);
  auto helper_process = std::make_unique<Subprocess>(options);

  CHECK_OK(helper_process->Start({helper, std::string(mode)}));
  return helper_process;
}

void SingleStepCountLoops(pid_t pid, const struct user_regs_struct& regs,
                          int& n_loop_head_seen) {
  uint64_t data =
      ptrace(PTRACE_PEEKTEXT, pid, GetIPFromUserRegs(regs), nullptr);
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
    std::optional<ProcessInfo> info = tracer.Join();
    ASSERT_TRUE(info.has_value());
    ProcessInfoLooksReasonable(*info);
    if (test_mode == "test-crash") {
      EXPECT_TRUE(WIFSIGNALED(info->status));
      EXPECT_EQ(WTERMSIG(info->status), SIGABRT);
    } else {
      EXPECT_EQ(info->status, 0);
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
        SingleStepCountLoops(pid, regs, n_loop_head_seen);
        return HarnessTracer::kKeepTracing;
      });
  tracer.Attach();

  std::optional<ProcessInfo> info = tracer.Join();
  ASSERT_TRUE(info.has_value());
  EXPECT_EQ(info->status, 0);
  ProcessInfoLooksReasonable(*info);

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
        if (GetSyscallNumberFromUserRegs(regs) == SYS_getcpu) {
          ++num_seen_getcpu;
        }
        return HarnessTracer::kKeepTracing;
      });
  tracer.Attach();

  std::optional<ProcessInfo> info = tracer.Join();
  ASSERT_TRUE(info.has_value());
  EXPECT_EQ(info->status, 0);
  ProcessInfoLooksReasonable(*info);

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
    std::optional<ProcessInfo> info = tracer.Join();

    ASSERT_TRUE(info.has_value());
    ASSERT_TRUE(WIFEXITED(info->status)) << "status = " << info->status;
    if (mode == HarnessTracer::kSyscall) {
      EXPECT_EQ(WEXITSTATUS(info->status), 12)
          << "SignalHelper() does 3 rounds of 4 types of causing SIGTRAP";
    } else {
      EXPECT_EQ(WEXITSTATUS(info->status), 11)
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
                         if (GetSyscallNumberFromUserRegs(regs) == SYS_getcpu) {
                           // asks the tracer to inject SIGUSR1 when it sees
                           // getcpu syscall
                           return HarnessTracer::kInjectSigusr1;
                         } else {
                           return HarnessTracer::kKeepTracing;
                         }
                       });
  tracer.Attach();
  std::optional<ProcessInfo> info = tracer.Join();
  ASSERT_TRUE(info.has_value());
  ProcessInfoLooksReasonable(*info);
  ASSERT_TRUE(WIFEXITED(info->status)) << "status = " << info->status;
  EXPECT_EQ(WEXITSTATUS(info->status), 1);
  std::string stdout_str;
  helper_process->Communicate(&stdout_str);
  LOG_INFO("Helper stdout:\n", stdout_str);
}

struct EarlyStopTestCase {
  std::string test_name;
  std::vector<int> stops;
  int expected_loop_count;
};

using EarlyStopTest = TestWithParam<EarlyStopTestCase>;

// On X86 ptrace uses trap flag to implement single-stepping. For reasons that
// are not clear, `popfq` would erroneously raises TF, and cause the tracee to
// keep firing SIGTRAPs after each insn. This test verifies that HarnessTracer
// can successfully stop single-stepping even if the bug is triggered.
TEST_P(EarlyStopTest, X86TrapFlagBug) {
#if defined(__aarch64__)
  GTEST_SKIP();
#endif
  const EarlyStopTestCase& test_case = GetParam();
  std::unique_ptr<Subprocess> helper_process =
      StartHelperProcess("test-x86-trap-flag-bug");

  int n_loop_head_seen = 0;
  auto curr_stop = test_case.stops.begin();
  HarnessTracer tracer(helper_process->pid(), HarnessTracer::kSingleStep,
                       [&](pid_t pid, const struct user_regs_struct& regs,
                           HarnessTracer::CallbackReason reason) {
                         if (reason != HarnessTracer::kSingleStepStop) {
                           return HarnessTracer::kKeepTracing;
                         }
                         SingleStepCountLoops(pid, regs, n_loop_head_seen);
                         if (curr_stop != test_case.stops.end() &&
                             n_loop_head_seen == *curr_stop) {
                           curr_stop++;
                           return HarnessTracer::kStopTracing;
                         }
                         return HarnessTracer::kKeepTracing;
                       });
  tracer.Attach();

  std::optional<ProcessInfo> info = tracer.Join();
  ASSERT_TRUE(info.has_value());
  EXPECT_EQ(info->status, 0);
  ProcessInfoLooksReasonable(*info);

  std::string stdout_str;
  helper_process->Communicate(&stdout_str);
  LOG_INFO("Helper stdout:\n", stdout_str);
  // Expecting exactly 5 loops + one more callback at same instruction pointer
  // executed before stop is requested.
  EXPECT_EQ(n_loop_head_seen, test_case.expected_loop_count);
}

INSTANTIATE_TEST_SUITE_P(
    EarlyStopTestInstantiation, EarlyStopTest,
    testing::ValuesIn<EarlyStopTestCase>({
        {"no_stop", {}, 100},
        {"1_stop", {5}, 55},  // First 50 loops stopped at 5th loop, next 50
        // loops not traced, and final 50 loops traced and not stopped.
        {"2_stops",
         {5, 10},
         10},  // First 50 loops stopped at 5th loop, next 50
        // loops not traced, and final 50 loops traced and stopped at 5th loop.
    }),
    [](const testing::TestParamInfo<EarlyStopTest::ParamType>& info) {
      return info.param.test_name;
    });

}  // namespace

}  // namespace silifuzz
