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

#include "./runner/disassembling_snap_tracer.h"

#include <sys/types.h>
#include <sys/user.h>

#include "./common/harness_tracer.h"
#include "./util/user_regs_util.h"

namespace silifuzz {

HarnessTracer::ContinuationMode DisassemblingSnapTracer::Step(
    pid_t pid, const user_regs_struct& regs,
    HarnessTracer::CallbackReason reason) {
  if (reason == HarnessTracer::kSignalStop) {
    return HarnessTracer::kStopTracing;
  }
  if (reason == HarnessTracer::kBecomingInactive) {
    was_in_snapshot_ = false;
    return HarnessTracer::kStopTracing;
  }
  // Flag indicating if the instruction pointer is in one of the snapshot memory
  // regions.
  bool in_snapshot =
      snapshot_.mapped_memory_map().Contains(GetIPFromUserRegs(regs));
  if (in_snapshot) {
    auto r = stepper_.StepInstruction(pid, regs, reason);
    // If the SnapshotStepper callback does not wants to keep tracing then
    // HarnessTracer will issue a PTRACE_CONT and won't invoke us
    // anymore. We need to catch this and reset was_in_snapshot_ b/c
    // there won't be another chance to do this inside the callback.
    was_in_snapshot_ = r == HarnessTracer::kKeepTracing;
    return r;
  } else {
    if (was_in_snapshot_) {
      was_in_snapshot_ = false;
      // We have just left the snapshot. Tell the tracer to PTRACE_CONT
      // until it sees a SIGSTOP
      return HarnessTracer::kStopTracing;
    }
    return HarnessTracer::kKeepTracing;
  }
}

}  // namespace silifuzz
