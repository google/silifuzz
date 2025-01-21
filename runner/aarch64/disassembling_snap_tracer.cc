// Copyright 2024 The SiliFuzz Authors.
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

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "./common/harness_tracer.h"
#include "./instruction/static_insn_filter.h"
#include "./util/checks.h"
#include "./util/itoa.h"

namespace silifuzz {

namespace {
// TODO(dougkwan): Share part of this code with DecodedInsn::FetchInstruction.
absl::StatusOr<std::string> FetchInstructionFromProcess(pid_t pid,
                                                        uint64_t addr) {
  if (addr % sizeof(uint32_t) != 0) {
    return absl::InternalError(
        absl::StrCat(HexStr(addr), " was not 32-bit aligned"));
  }

  // PEEKTEXT reads 64-bit at 'addr'. This code only works for little-endian
  // aarch64.
  uint32_t insn;
  insn = ptrace(PTRACE_PEEKTEXT, pid, AsPtr(addr), nullptr);
  if (errno != 0) {
    return absl::InternalError(
        absl::StrCat(HexStr(addr), " was not mapped: ", ErrnoStr(errno)));
  }
  return std::string(reinterpret_cast<char*>(&insn), sizeof(insn));
}

}  // namespace

uint64_t DisassemblingSnapTracer::GetInstructionPointer(
    const struct user_regs_struct& regs) {
  return regs.pc;
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

  const uint64_t addr = regs.pc;
  absl::StatusOr<std::string> insn_or = FetchInstructionFromProcess(pid, addr);
  if (!insn_or.ok()) {
    LOG_ERROR(insn_or.status().message());
    // We couldn't fetch the instruction meaning this snapshot likely causes
    // SEGV. Let HarnessTracer take care of proper signal delivery.
    return HarnessTracer::kKeepTracing;
  }

  // Reapply the static instruction filter.
  //
  // This filter should already be applied in the fuzzing process, but old
  // snapshots may bypass it if they were fed as side inputs to generate the
  // corpus (e.g. old false positives that were not removed).
  //
  // This step should have minimal overhead, and thus we opt to apply it here
  // too for defense in depth (as opposed to relying on us remembering to delete
  // bad snapshots from the corpus).
  if (!StaticInstructionFilter<AArch64>(*insn_or)) {
    trace_result_.early_termination_reason = "Has problematic instructions.";
    return HarnessTracer::kInjectSigusr1;
  }

  // Disassemble the instruction.
  disassembler_.Disassemble(
      addr, reinterpret_cast<const uint8_t*>(insn_or->data()), insn_or->size());
  trace_result_.disassembly.emplace_back(
      absl::StrCat(trace_result_.instructions_executed, " addr=", HexStr(addr),
                   " ", disassembler_.FullText()));
  VLOG_INFO(1, trace_result_.disassembly.back());

  // TODO(dougkwan): Implement no memory access filter on aarch64.
  // Note that we cannot trust Capstone to tell us precisely if an instruction
  // accesses memory or not. We will need to do something else.
  return HarnessTracer::kKeepTracing;
}

}  // namespace silifuzz
