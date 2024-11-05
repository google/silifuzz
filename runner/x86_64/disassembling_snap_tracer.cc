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

#include <cstdint>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "./common/harness_tracer.h"
#include "./instruction/decoded_insn.h"
#include "./util/checks.h"
#include "./util/itoa.h"

namespace silifuzz {

uint64_t DisassemblingSnapTracer::GetInstructionPointer(
    const struct user_regs_struct& regs) {
  return regs.rip;
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
      trace_result_.disassembly.emplace_back(absl::StrCat(
          trace_result_.instructions_executed, " addr=", HexStr(addr),
          " size=", insn_or->length(), " ", insn_or->DebugString()));
      VLOG_INFO(1, trace_result_.disassembly.back());
    }
    if (!insn_or->is_allowed_in_runner() &&
        options_.filter_non_deterministic_insn) {
      trace_result_.early_termination_reason =
          absl::StrCat("Non-deterministic insn ", insn_or->mnemonic());
      return HarnessTracer::kInjectSigusr1;
    }
    if (options_.x86_filter_split_lock && insn_or->is_locking()) {
      auto may_have_split_lock_or = insn_or->may_have_split_lock(regs);
      if (!may_have_split_lock_or.ok()) {
        // We cannot determine if there is a split-lock because of an internal
        // error in may_have_split_lock(). Abort tracing.
        trace_result_.early_termination_reason = absl::StrCat(
            "may_have_split_lock() failed for insn ", insn_or->mnemonic());
        return HarnessTracer::kInjectSigusr1;
      }

      if (may_have_split_lock_or.value()) {
        trace_result_.early_termination_reason =
            absl::StrCat("Split-lock insn ", insn_or->mnemonic());
        return HarnessTracer::kInjectSigusr1;
      }
    }
    if (options_.x86_filter_vsyscall_region_access) {
      constexpr uintptr_t kVSyscallRegionAddress = 0xffffffffff600000ULL;
      constexpr uintptr_t kVSyscallRegionSize = 0x800000;
      absl::StatusOr<bool> may_access_vsyscall_region_or =
          insn_or->may_access_region(regs, kVSyscallRegionAddress,
                                     kVSyscallRegionSize);
      if (!may_access_vsyscall_region_or.ok()) {
        // We cannot determine if instruction accesses the legacy vsyscall
        // region because of an internal error in may_access_region(). Abort
        // tracing.
        trace_result_.early_termination_reason = absl::StrCat(
            "may_access_region() failed for insn ", insn_or->mnemonic());
        return HarnessTracer::kInjectSigusr1;
      }
      if (may_access_vsyscall_region_or.value()) {
        trace_result_.early_termination_reason =
            absl::StrCat("May access vsyscall region ", insn_or->mnemonic());
        return HarnessTracer::kInjectSigusr1;
      }
    }
    if (options_.filter_memory_access && insn_or->may_access_memory()) {
      // We need to check if this is the ending address because on the x86,
      // the exit sequence is an indirect call.
      const uint64_t end_state_rip =
          snapshot_.ExtractRip(snapshot_.expected_end_states()[0].registers());
      if (regs.rip != end_state_rip) {
        trace_result_.early_termination_reason = "Memory access not allowed";
        return HarnessTracer::kInjectSigusr1;
      }
    }
  } else {
    VLOG_INFO(1, HexStr(addr), ": <undecodable>");
    prev_instruction_decoding_failed_ = true;
  }
  prev_instruction_addr_ = addr;

  return HarnessTracer::kKeepTracing;
}

}  // namespace silifuzz
