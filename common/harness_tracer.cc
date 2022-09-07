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
#include <sys/user.h>

#include <csignal>
#include <cstddef>
#include <cstdlib>
#include <memory>
#include <optional>
#include <thread>
#include <utility>

#include "absl/synchronization/mutex.h"
#include "./util/checks.h"
#include "./util/itoa.h"
#include "./util/ptrace_util.h"
#include "./util/x86_traps.h"

namespace silifuzz {

HarnessTracer::HarnessTracer(pid_t pid, Mode mode, Callback callback)
    : pid_(pid),
      mode_(mode),
      callback_(std::move(callback)),
      tracer_thread_(),
      exit_status_() {}

void HarnessTracer::Step(int signal) const {
  PTraceOrDie(mode_ == kSingleStep ? PTRACE_SINGLESTEP : PTRACE_SYSCALL, pid_,
              0, signal);
}

void HarnessTracer::Attach() {
  CHECK(tracer_thread_ == nullptr);
  tracer_thread_ = std::make_unique<std::thread>([this] {
    std::optional<int> status = this->EventLoop();
    absl::MutexLock l(&exit_status_mutex_);
    exit_status_ = status;
  });
}

std::optional<int> HarnessTracer::Join() {
  CHECK(tracer_thread_ != nullptr);
  CHECK(tracer_thread_->joinable());
  VLOG_INFO(2, "Join()-ing tracer on PID ", pid_);
  tracer_thread_->join();
  tracer_thread_ = nullptr;
  std::optional<int> status;
  {
    absl::MutexLock l(&exit_status_mutex_);
    status.swap(exit_status_);
  }
  VLOG_INFO(2, "Tracer on PID ", pid_, " exited");
  return status;
}

void HarnessTracer::ContinueTraceeWithSignal(int signal) const {
  if (signal != 0) {
    VLOG_INFO(2, "Injecting signal ", signal);
  }
  PTraceOrDie(PTRACE_CONT, pid_, 0, signal);
}

bool HarnessTracer::Trace(int status, bool is_active) const {
  VLOG_INFO(2, "Trace: ", HexStr(status), " active = ", is_active);
  if (WSTOPSIG(status) == SIGSTOP) {
    // The tracee requested to toggle tracing mode.
    VLOG_INFO(2, "PID ", pid_, " raised SIGSTOP");

    if (!is_active) {
      // entering active state.
      Step();
    } else {
      // else, we are leaving the active state. The tracer keeps itself attached
      // but won't receive syscall/singlestep events only signals until the
      // next SIGSTOP.

      // Suppress trap flag.
      // For reasons that are not clear the final popfq in RestoreUContext()
      // erroneously raises TF meaning that despite PTRACE_CONT the tracee will
      // keep firing unexpected SIGTRAPs for every instruction.
      // Some related discussions and description of the problem can be found
      // in [1] and [2]. [3] is the current ptrace helper code in the kernel.
      // [1] http://lkml.iu.edu/hypermail/linux/kernel/0501.0/0066.html
      // [2] https://lore.kernel.org/patchwork/patch/544554/
      // [3]
      // https://elixir.bootlin.com/linux/latest/source/arch/x86/kernel/step.c
      //
      // The TL;DR of the above is that on X86 ptrace uses TF to implement
      // single-stepping but the kernel hides this from user-space except when
      // pushf leaks the value.
      struct user_regs_struct regs;
      PTraceOrDie(PTRACE_GETREGS, pid_, 0, &regs);
      regs.eflags &= ~kX86TrapFlag;
      // Use POKEUSER instead of more readable SETREGS because the former allows
      // updating just the one register. SETREGS can return unexpected EIO when
      // the tracee has non-default segment registers. See details here:
      // https://elixir.bootlin.com/linux/latest/source/arch/x86/kernel/ptrace.c#L150
      PTraceOrDie(PTRACE_POKEUSER, pid_,
                  (void*)offsetof(struct user_regs_struct, eflags),
                  regs.eflags);
      ContinueTraceeWithSignal();
    }
    return !is_active;
  }

  // Not active, be as transparent as possible and keep injecting signals.
  if (!is_active) {
    siginfo_t info;
    PTraceOrDie(PTRACE_GETSIGINFO, pid_, 0, &info);
    ContinueTraceeWithSignal(info.si_signo);
    return false;
  }

  struct user_regs_struct regs;
  PTraceOrDie(PTRACE_GETREGS, pid_, 0, &regs);
  siginfo_t info;
  PTraceOrDie(PTRACE_GETSIGINFO, pid_, 0, &info);

  // The tracee is now in ptrace-stopped state and the tracer is active.
  CallbackReason reason = [&]() {
    if (WSTOPSIG(status) == (SI_KERNEL | SIGTRAP)) {
      VLOG_INFO(2, "system call at ", HexStr(regs.rip),
                ", orig_rax = ", regs.orig_rax);
      return kSyscallStop;
    }
    switch (info.si_signo) {
      case SIGTRAP:
        if (info.si_code == SI_KERNEL || info.si_code == 0 /* raise */
            || mode_ == kSyscall /* tracing syscalls but got a trap */) {
          // The SIGTRAP occurred in the code (e.g. int3), this is either an
          // endpoint or an embedded trap. Inject it and continue tracing.
          return kSignalStop;
        } else if (info.si_code == TRAP_TRACE || info.si_code == TRAP_BRKPT ||
                   info.si_code == 5) {
          // PTRACE_SINGLESTEP does not document si_code values but
          // experimentally this appears to hold
          // syscall instruction in RestoreUContext triggers TRAP_BRKPT branch
          // in SINGLESTEP mode.
          // 5 is TRAP_UNK, an "undiagnosed trap" according to
          // include/uapi/asm-generic/siginfo.h. In practice this seems to
          // happen on entering a sighandler in the tracee.
          return kSingleStepStop;
        } else {
          LOG_FATAL("unexpected siginfo = ", info.si_signo,
                    " si_code = ", HexStr(info.si_code),
                    " si_errno = ", info.si_errno);
        }
      default:
        return kSignalStop;
    }
  }();

  int signal = reason == kSignalStop ? info.si_signo : 0;
  ContinuationMode m = callback_(pid_, regs, reason);
  switch (m) {
    case kKeepTracing:
      Step(signal);
      break;
    case kStopTracing:
      callback_(pid_, regs, kBecomingInactive);
      ContinueTraceeWithSignal(signal);
      break;
    case kInjectSigusr1:
      VLOG_INFO(2, "callback requested to inject SIGUSR1 at ",
                HexStr(regs.rip));
      callback_(pid_, regs, kBecomingInactive);
      ContinueTraceeWithSignal(SIGUSR1);
      break;
  }
  return true;
}

std::optional<int> HarnessTracer::EventLoop() const {
  VLOG_INFO(1, "Attaching to ", pid_);
  // Use SEIZE instead of ATTACH since the latter sends an unwanted SIGSTOP.
  if (PTraceOrDieExitedOk(PTRACE_SEIZE, pid_, 0, 0)) {
    VLOG_INFO(1, "Attached to PID ", pid_);
  }  // else fallthrough to the following WaitpidToStop() to get the status

  std::optional<int> status;
  bool is_active = false;
  bool has_set_opts = false;
  while (WaitpidToStop(pid_, &status)) {
    if (!has_set_opts) {
      PTraceOrDie(PTRACE_SETOPTIONS, pid_, 0, PTRACE_O_TRACESYSGOOD);
      has_set_opts = true;
    }
    is_active = Trace(status.value(), is_active);
  }
  return status;
}

}  // namespace silifuzz
