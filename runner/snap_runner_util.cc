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

#include "./runner/snap_runner_util.h"

#include <signal.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>

#include "./common/snapshot_enums.h"
#include "./snap/exit_sequence.h"
#include "./util/checks.h"
#include "./util/ucontext/signal.h"
#include "./util/ucontext/ucontext.h"
#include "./util/ucontext/ucontext_types.h"
#include "./util/ucontext/x86_64/traps.h"

namespace silifuzz {

using snapshot_types::EndSpot;

UContext<Host> snap_exit_context;

namespace {

// Before entering a Snap, the runner's context is saved here. After a Snap
// finishes normally, control flow continues after this saved context.
UContext<Host> runner_return_context;

// Bool indicating if we are about to enter a Snap's context. This is used by
// RunSnap() below to distinguish whether we have just saved the runner's
// context or returned to a saved context from a Snap.
bool enter_snap_context;

// Register state and signal info if a Snap causes a signal.
struct SnapSignalContext {
  enum LinkerInitialized { LINKER_INITIALIZED };

  // True value indicates that the signal did happen and the rest of the
  // fields will be populated.
  bool signal_occurred;
  // Same as snap_exit_context except when a signal occurs during Snap
  // execution. Populated by the signal handler based on the ucontext_t passed
  // by the kernel.
  ucontext_t ucontext;
  // siginfo_t associated with the signal.
  siginfo_t sig_info;
  // Other registers not captured in ucontext.
  ExtraSignalRegs extra_gregs;

  // Construct a zero-initialized SnapSignalContext that is initialized by
  // linker. This is required to avoid runtime initialiazation of globals.
  constexpr SnapSignalContext(LinkerInitialized)
      : signal_occurred(false),
        ucontext({0}),
        sig_info({0}),
        extra_gregs({0}) {}
};

SnapSignalContext snap_signal_context(SnapSignalContext::LINKER_INITIALIZED);

}  // namespace

bool IsInsideSnap() { return enter_snap_context; }

// Assembly implementation of the exit point.
// In conjuction with RunnerReentry() saves the context at the Snap exit into
// `snap_exit_context`.
extern "C" void SnapExitImpl();

// SnapExitImpl jumps to this for switching back into the runner's context.
// 'arg1' is the value of the first argument register (e.g. %rdi on x86_64) and
// 'stack_pointer' is the stack pointer (e.g. %rsp on x86_64) at snap exit.
// These are passed to here so that RunnerReentry() can fix up the context. In
// addition, this function also fixes up the program counter (%rip on x86_64) of
// the snap exit context. We do fix up in here instead of SnapExitImpl() to
// simplify assembly implementation. C++ is more readable and less error prone
// than assembly. Control flow resumes from RunnerReturnContext after this
// function.

// The "C" linkage allows assembly function SnapExitImpl() to call this without
// using name mangling.
#if defined(__x86_64__)
extern "C" void RunnerReentry(uint64_t arg1, uint64_t stack_pointer) {
  // Fix up registers not saved in snap_exit_context.
  snap_exit_context.gregs.rip = FixUpReturnAddress<X86_64>(
      *reinterpret_cast<const uint64_t*>(stack_pointer));

  // Pop return address to get stack_pointer (%rsp) value before snap exit
  // sequence.
  snap_exit_context.gregs.rsp = stack_pointer + sizeof(uint64_t);

  // Fix up first argument register in the ABI (%rdi) that was overwritten by
  // SnapExitImpl().
  snap_exit_context.gregs.rdi = arg1;

  // Fix up mxcsr_mask. Some AMD CPUs have bit 17 of mxcsr_mask set but
  // not all x86_64 CPUs do.
  FixUpRegsPadding(&snap_exit_context);

  // Signal to RunSnap() that we've left the Snap context
  enter_snap_context = false;
  RestoreUContextNoSyscalls(&runner_return_context);
  __builtin_unreachable();
}
#elif defined(__aarch64__)
extern "C" void RunnerReentry(uint64_t x0, uint64_t x30, uint64_t pc,
                              uint64_t sp) {
  // Fix up registers not saved in snap_exit_context.
  snap_exit_context.gregs.x[0] = x0;
  snap_exit_context.gregs.x[30] = x30;
  snap_exit_context.gregs.pc = FixUpReturnAddress<AArch64>(pc);
  snap_exit_context.gregs.sp = sp;

  FixUpRegsPadding(&snap_exit_context);

  // Signal to RunSnap() that we've left the Snap context
  enter_snap_context = false;
  RestoreUContextNoSyscalls(&runner_return_context);
  __builtin_unreachable();
}
#else
#error "Unsupported architecutre"
#endif

void RunnerReentryFromSignal(const ucontext_t& libc_ucontext,
                             const siginfo_t& sig_info) {
  CHECK(IsInsideSnap());
  snap_signal_context.signal_occurred = true;
  snap_signal_context.sig_info = sig_info;
  snap_signal_context.ucontext = libc_ucontext;
  SaveExtraSignalRegsNoSyscalls(&snap_signal_context.extra_gregs);
  // Signal to RunSnap() that we've left the Snap context
  enter_snap_context = false;
  RestoreUContextNoSyscalls(&runner_return_context);
  __builtin_unreachable();
}

EndSpot RunSnap(const UContext<Host>& context) {
  snap_signal_context.signal_occurred = false;
  enter_snap_context = true;

  SaveUContextNoSyscalls(&runner_return_context);
  // We reach this point either by returning from SaveUContextNoSyscalls()
  // above or from a snap exit. In the latter case, enter_snap_context is
  // cleared.
  if (enter_snap_context) {
    RestoreUContextNoSyscalls(&context);
    __builtin_unreachable();
  }
  // Otherwise, the snap has just finished executing
  EndSpot end_spot;
  if (snap_signal_context.signal_occurred) {
    ConvertGRegsFromLibC(snap_signal_context.ucontext,
                         snap_signal_context.extra_gregs, &end_spot.gregs);
    ConvertFPRegsFromLibC(snap_signal_context.ucontext, &end_spot.fpregs);
    end_spot.signum = snap_signal_context.sig_info.si_signo;
    end_spot.sig_address = AsInt(snap_signal_context.sig_info.si_addr);
    ConvertSignalRegsFromLibC(snap_signal_context.ucontext, &end_spot.sigregs);
  } else {
    end_spot.signum = 0;
    end_spot.sig_address = 0;
    end_spot.sigregs = {};
    end_spot.gregs = snap_exit_context.gregs;
    end_spot.fpregs = snap_exit_context.fpregs;
    // Sanitize gregs and fpregs.
    ZeroOutGRegsPadding(&end_spot.gregs);
    ZeroOutFPRegsPadding(&end_spot.fpregs);
  }

#if defined(__x86_64__)
  // When under ptrace the trap flag leaks in siginfo. Hide the flag so that
  // we don't produce unexpected end states.
  // This clobbers the trace flag even if it was legitimately raised by the
  // snapshot itself.  This is not a concern because the rest of SiliFuzz infra
  // does not expect such behavior and will bail as soon as the flag is
  // raised.
  // TODO(ksteuck): [as-needed] We can be more selective about when to hide the
  // flag (e.g. do this when the process is being traced).
  end_spot.gregs.eflags &= ~kX86TrapFlag;
#endif

  return end_spot;
}

}  // namespace silifuzz
