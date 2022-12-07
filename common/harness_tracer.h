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

#ifndef THIRD_PARTY_SILIFUZZ_COMMON_HARNESS_TRACER_H_
#define THIRD_PARTY_SILIFUZZ_COMMON_HARNESS_TRACER_H_

#include <sys/types.h>
#include <sys/user.h>

#include <functional>
#include <memory>
#include <optional>
#include <thread>  // NOLINT

#include "absl/base/thread_annotations.h"
#include "absl/synchronization/mutex.h"
#include "./util/checks.h"

namespace silifuzz {

#if defined(__x86_64__)
inline uint64_t GetInstructionPointer(const user_regs_struct& regs) {
  return regs.rip;
}

inline uint64_t GetSyscallNumber(const user_regs_struct& regs) {
  // Some syscalls clobber rax but orig_rax preserves the value.
  return regs.orig_rax;
}
#elif defined(__aarch64__)
inline uint64_t GetInstructionPointer(const user_regs_struct& regs) {
  return regs.pc;
}

inline uint64_t GetSyscallNumber(const user_regs_struct& regs) {
  return regs.regs[8];
}
#else
#error "Unsupported architecture"
#endif

// HarnessTracer is a ptrace-based tracing facility for the subprocess harness.
// The typical usage looks like this:
//
// In parent tracer process:
//   ... pid = <pid of tracee>
//   HarnessTracer tracer(pid, mode, callback_fn);
//   tracer.Attach();
//   ... callback_fn receives notifications of the "intersting things" in tracee
//   ... initiate tracee exit (e.g. kill(pid))
//   status = tracer.Join();  // status is the exit status of tracee
// In tracee:
//   raise(SIGSTOP);  // toggle the tracer active mode
//   ... do intersting things
//   raise(SIGSTOP);  // deactivate tracer
//
// A newly created HarnessTracer instance needs to be attached to the tracee
// and activated to start receiving events.
// The tracee toggles the active state by raise(SIGSTOP).
// Attach() starts a ptrace event loop on a separate thread but keeps the
// HarnessTracer in an "inactive" state i.e. it won't be listening for any
// events defined by the `mode` c-tor parameter. While inactive the tracer will
// be receiving and passing along to the tracee any ptrace-stop events e.g.
// signals. See "Stopped states" in ptrace(2) for details.
//
// While in active state, the HarnessTracer will listen for the events requested
// by `mode` and pass them to the user-provided TraceCallback. The ptrace events
// will be processes as well but the callback is not notified of them.
//
// NOTE: Once Attach()-ed the HarnessTracer will keep the tracee
// under its control until the tracee exits i.e. Join() blocks until the
// tracee calls exit() or crashes.
//
// This class is thread-compatible.
class HarnessTracer {
 public:
  // Represents tracing mode.
  enum Mode {
    // Trace syscalls. Each syscall generates two events for the callback, one
    // before and one after the call.
    // We are leaving it up to the callback to do something useful when it sees
    // a syscall.
    // In the SiliFuzz setting we'd like are preventing snapshots from making
    // syscalls by
    // inject a predefined signal (SIGUSR1) into the playing process whenever a
    // syscall is detected
    // that originated from within a snapshot. The process then interprets this
    // as a
    // signal to stop executing the snapshot and return early. Similar technique
    // can be used to detect snapshots executing CPUID or similar instructions.
    kSyscall,

    // Single-step instruction by instruction. An event will be generated before
    // each instruction with %rip pointing to the first byte of the instruction
    // to be executed.
    kSingleStep,
  };

  // Describes the outcome of a callback.
  enum ContinuationMode {
    // When the callback returns kKeepTracing the tracer will keep running in
    // the chosen Mode (kSyscall, kSingleStep).
    kKeepTracing,

    // When the callback returns kStopTracing the callback will stop receiving
    // further notifications from the tracer until the tracee toggles the
    // active mode twice.
    kStopTracing,

    // When the callback returns kInjectSigusr1 the tracer will inject a SIGUSR1
    // into the tracee at the current execution point.
    kInjectSigusr1,
  };

  // Describes the reason for the callback.
  enum CallbackReason {
    // Stop at syscall (only available when mode is kSyscall).
    kSyscallStop,

    // Stop due to single-stepping (only available when mode is kSingleStep).
    kSingleStepStop,

    // Stop due to a signal delivery.
    kSignalStop,

    // Callback due to the tracing swiching from active to inactive. In practice
    // this means there will be no more callbacks from harness until the tracee
    // flips the tracer back into active mode.
    kBecomingInactive,
  };

  // User-defined callback that receives notifications of ptrace events.
  // pid_t is the PID of the thread being traced, user_regs_struct contains
  // the CPU register state of the tracee returned by ptrace(PTRACE_GETREGS).
  // `status` is the value status of the tracee returned by waitpid(2).
  // The return value of the callback tells the tracer how to continue past the
  // current ptrace-stop. See ContinuationMode.
  using Callback = std::function<ContinuationMode(
      pid_t, const user_regs_struct&, CallbackReason reason)>;

  // Create a tracer for the given process `pid` in the specified tracing
  // `mode`. `callback` will be invoked for every intersting event as defined by
  // `mode`.
  HarnessTracer(pid_t pid, Mode mode, Callback callback);

  // Movable, but not copyable (not just a data holder).
  HarnessTracer(const HarnessTracer&) = delete;
  HarnessTracer(HarnessTracer&&) = default;
  HarnessTracer& operator=(const HarnessTracer&) = delete;
  HarnessTracer& operator=(HarnessTracer&&) = default;

  // REQUIRES: !is_attached()
  ~HarnessTracer() { CHECK(!is_attached()); }

  // Initiates process tracing.
  // REQUIRES: !is_attached()
  void Attach();

  // Blocks until the tracee exits.
  // CAVEAT: The caller must first initiate the tracee shutdown but not make any
  // calls that would waitpid() on the tracee. For the harness binary this
  // typically means closing its STDIN.
  // Returns the tracee exit status or nullopt if we missed it.
  // REQUIRES: is_attached()
  std::optional<int> Join();

  // Whether or not Attach() has been called.
  bool is_attached() const { return tracer_thread_ != nullptr; }

 private:
  // Runs the ptrace event loop. See class-level comment for details.
  // Returns the tracee exit status or nullopt if we missed it.
  // REQUIRES: is_attached().
  std::optional<int> EventLoop() const;

  // Processes a given ptrace stop event identified by `status`.
  // `status` is the waitpid's wstatus of the tracee. `is_active` is the current
  // state of the tracer (active or inactive).
  // Returns active state of the tracer after processsing the current stop
  // event.
  bool Trace(int status, bool is_active) const;

  // Releases the tracee until the next ptrace-stop event (see class-level
  // comment). If `signal` is >0 injects the corresponding signal.
  // REQUIRES: The tracee must be in one of the stopped states which is ensured
  // by invoking waitpid() and checking WIFSTOPPED(status).
  void Step(int signal = 0) const;

  // Continues (as in PTRACE_CONT) the tracee. When signal != 0 injects the
  // signal into the tracee.
  // REQUIRES: The tracee must be in one of the stopped states.
  void ContinueTraceeWithSignal(int signal = 0) const;

  // Gets the register state of the tracee.
  void GetRegSet(struct user_regs_struct& regs) const;

  // c-tor parameters
  pid_t pid_;
  Mode mode_;
  Callback callback_;

  // Handle for the fiber running the ptrace event loop. Nullptr when
  // the tracer is not attached.
  std::unique_ptr<std::thread> tracer_thread_;

  // Lock for status_ below.
  absl::Mutex exit_status_mutex_;

  // Tracee exit status.
  std::optional<int> exit_status_ ABSL_GUARDED_BY(exit_status_mutex_);
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_COMMON_HARNESS_TRACER_H_
