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

#ifndef THIRD_PARTY_SILIFUZZ_RUNNER_SNAP_RUNNER_UTIL_H_
#define THIRD_PARTY_SILIFUZZ_RUNNER_SNAP_RUNNER_UTIL_H_
// Low-level Snap execution primitives.
// These handle switching context into a Snap and returning from it.
//
// The runner executes Snaps without using any system calls, hence it uses
// no-syscalls variants of the UContext manipulation functions. The following
// are not switched between contexts:
//   - segment bases fs_base and gs_base
//   - signal masks
//
// In addition, fs_base and gs_base are almost always reset to zero by
// RestoreUContextNoSyscall.
//
// We could end a Snap via an exceptions, which causes the exact register
// state at the exit to be captured but exceptions are slow due to two required
// context switches in and out of the kernel.  Instead of using exceptions,
// Snaps end by calling to a pre-defined address that leads back to the
// runner. This is faster than using exceptions. The runner inspects stack
// contents of the Snapshot to figure out the actual end point address.
// RunnerReentry() below needs to fix up the stack to include the address after
// Snap exit sequence in the memory end state.
//
// TODO(dougkwan): [as-needed] For RISC architectures, function calls usually
// do not write return addesses in memory but in registers. We need to fix up
// differently on RISC CPUs. The exit sequence on a RISC CPU probably requires
// saving return register first and then calling the exit location.
//
// Thread safety note: Except when denoted otherwise, all functions in this file
// are not thread-safe as these manipulate global state without locking.

#include <ucontext.h>

#include <csignal>
#include <cstddef>
#include <cstdint>

#include "./runner/endspot.h"
#include "./util/ucontext/signal.h"
#include "./util/ucontext/ucontext_types.h"

extern "C" void SnapExitImpl();

namespace silifuzz {

// This stores register states when the snap exit point is entered.
// The value stored here persists until the next call of
// SnapExitImpl().
extern "C" UContext<Host> snap_exit_context;

// Returns true if the execution is currently inside a Snap. Can be used inside
// a signal handler to determine if the signal was raised while executing a
// Snap. See RunSnap() below.
bool IsInsideSnap();

// Resumes normal runner execution after a Snap encountered a signal.
// Similar to RunnerReentry() except uses the provided ucontext_t instead of the
// current CPU context.
//
// REQUIRES: IsInsideSnap() == true
void RunnerReentryFromSignal(const ucontext_t& libc_ucontext,
                             const siginfo_t& sig_info);

// Switches to 'context' to execute code in Snap. After the snap exits,
// switches back to the runner's context and returns to caller.
// Stores CPU state at the time of Snap exit in 'end_spot'.
// The caller MUST install a custom signal handler that invokes
// RunnerReentryFromSignal() for RunSnap() to work properly for sig-causing
// snaps.
//
// REQUIRES: Called after calling InitSnapExit().
void RunSnap(const UContext<Host>& context, EndSpot& end_spot);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_RUNNER_SNAP_RUNNER_UTIL_H_
