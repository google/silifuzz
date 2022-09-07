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

#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "./common/decoded_insn.h"
#include "./common/harness_tracer.h"
#include "./util/checks.h"
#include "./util/itoa.h"

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
  // Flag indicating if regs.rip belongs to one of the snapshot memory regions.
  bool in_snapshot = snapshot_.mapped_memory_map().Contains(regs.rip);
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

HarnessTracer::ContinuationMode
DisassemblingSnapTracer::SnapshotStepper::StepInstruction(
    pid_t pid, const struct user_regs_struct& regs,
    HarnessTracer::CallbackReason reason) {
  if (trace_result_.instructions_executed++ >
          options_.instruction_count_limit &&
      options_.instruction_count_limit > 0) {
    trace_result_.early_termination_reason = "Reached instruction limit";
    return HarnessTracer::kInjectSigusr1;
  }

  const uint64_t addr = regs.rip;
  absl::StatusOr<DecodedInsn> insn_or = DecodedInsn::FromLiveProcess(pid, addr);
  if (!insn_or.ok()) {
    LOG_ERROR(insn_or.status().message());
    // We couldn't fetch the instruction meaning this snapshot likely causes
    // SEGV. Let HarnessTracer take care of proper signal delivery.
    return HarnessTracer::kKeepTracing;
  }
  if (insn_or->is_valid()) {
    if (prev_instruction_decoding_failed_) {
      trace_result_.early_termination_reason = absl::StrCat(
          HexStr(addr), ": Insn at ", HexStr(prev_instruction_addr_),
          " didn't decode but was still executed");
      return HarnessTracer::kInjectSigusr1;
    }
    prev_instruction_decoding_failed_ = false;
    // suppress multiple lines of identical `repn` and `jmp .`.
    if (prev_instruction_addr_ != addr) {
      VLOG_INFO(1, HexStr(addr), ": [", insn_or->length(), "] ",
                insn_or->DebugString());
      trace_result_.disassembly.emplace_back(insn_or->DebugString());
    }
    if (!insn_or->is_deterministic()) {
      trace_result_.early_termination_reason =
          absl::StrCat("Non-deterministic insn ", insn_or->mnemonic());
      return HarnessTracer::kInjectSigusr1;
    }
  } else {
    VLOG_INFO(1, HexStr(addr), ": <undecodable>");
    prev_instruction_decoding_failed_ = true;
  }
  prev_instruction_addr_ = addr;

  return HarnessTracer::kKeepTracing;
}

}  // namespace silifuzz
