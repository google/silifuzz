// Copyright 2025 The SiliFuzz Authors.
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

#include "./tracing/native_tracer.h"

#include <sys/uio.h>
#include <sys/user.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <utility>

#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "./common/harness_tracer.h"
#include "./common/proxy_config.h"
#include "./common/snapshot.h"
#include "./runner/driver/runner_driver.h"
#include "./runner/make_snapshot.h"
#include "./runner/runner_provider.h"
#include "./tracing/tracer.h"
#include "./util/arch.h"
#include "./util/checks.h"
#include "./util/itoa.h"
#include "./util/ptrace_util.h"
#include "./util/ucontext/serialize.h"
#include "./util/ucontext/ucontext_types.h"

namespace silifuzz {

namespace {

void SetGRegs(const pid_t pid, user_regs_struct& regs) {
  struct iovec io{&regs, sizeof(regs)};
  PTraceOrDie(PTRACE_SETREGSET, pid, (void*)NT_PRSTATUS, &io);
}

void DeserializeUserRegsStruct(const user_regs_struct& regs,
                               GRegSet<Host>* dst) {
#if defined(__x86_64__)
  // This abuses the fact that the legacy format is a byte dump of
  // user_regs_struct.
  CHECK_EQ(
      serialize_internal::DeserializeGRegs<X86_64>(&regs, sizeof(regs), dst),
      sizeof(regs));
#elif defined(__aarch64__)
  for (size_t i = 0; i < 31; ++i) {
    dst->x[i] = regs.regs[i];
  }
  dst->sp = regs.sp;
  dst->pc = regs.pc;
  dst->pstate = regs.pstate & kPStateMask;
#else
  LOG_FATAL(
      "DeserializeUserRegsStruct is not supported only on this architecture");
#endif
}

void SerializeUserRegsStruct(const GRegSet<Host>& regs, user_regs_struct* dst) {
#if defined(__x86_64__)
  // This abuses the fact that the legacy format is a byte dump of
  // user_regs_struct.
  CHECK_EQ(serialize_internal::SerializeLegacyGRegs(regs, dst, sizeof(*dst)),
           sizeof(*dst));
#elif defined(__aarch64__)
  for (size_t i = 0; i < 31; ++i) {
    dst->regs[i] = regs.x[i];
  }
  dst->sp = regs.sp;
  dst->pc = regs.pc;
  dst->pstate = regs.pstate;
#else
  LOG_FATAL("SerializeUserRegsStruct is not supported on this architecture");
#endif
}

}  // namespace

absl::Status NativeTracer::InitSnippet(
    absl::string_view instructions, const TracerConfig<Host>& tracer_config,
    const FuzzingConfig<Host>& fuzzing_config) {
  ASSIGN_OR_RETURN_IF_NOT_OK(
      Snapshot snapshot,
      MakeRawInstructions(instructions, MakingConfig::Quick(RunnerLocation())));
  snapshot_ = std::make_unique<Snapshot>(std::move(snapshot));

  code_start_address_ = snapshot_->ExtractRip(snapshot_->registers());
  CHECK_EQ(snapshot_->expected_end_states().size(), 1);
  code_end_address_ =
      snapshot_->expected_end_states()[0].endpoint().instruction_address();
  VLOG_INFO(
      2, "Finish making snapshot, start address: ", HexStr(code_start_address_),
      " end address: ", HexStr(code_end_address_));
  state_ = TracerState::kReady;
  VLOG_INFO(1, "entering ready state");
  return absl::OkStatus();
};

absl::Status NativeTracer::Run(size_t max_insn_executed) {
  CHECK(state_ == TracerState::kReady);
  state_ = TracerState::kPreTracing;
  VLOG_INFO(1, "entering pre-tracing state");
  // TODO(herooutman): consider to add runner location to tracer config.
  ASSIGN_OR_RETURN_IF_NOT_OK(
      RunnerDriver runner_driver,
      RunnerDriverFromSnapshot(*snapshot_, RunnerLocation()));

  size_t traced_insn_count = 0;
  absl::StatusOr<RunnerDriver::RunResult> run_result = runner_driver.TraceOne(
      snapshot_->id(),
      [&](pid_t pid, const user_regs_struct& regs,
          HarnessTracer::CallbackReason reason)
          -> HarnessTracer::ContinuationMode {
        if (pid_ == 0) pid_ = pid;
        if (reason != HarnessTracer::kSingleStepStop || ShouldStopTracing())
          return NextContinuationMode();

        uint64_t addr = silifuzz::GetInstructionPointer(regs);
        gregs_cache_.emplace(regs);
        if (state_ == TracerState::kPreTracing) {
          if (addr == code_start_address_) {
            // Note that the start address can be reached multiple times. Only
            // invoke the BeforeExecution callback the first time.
            BeforeExecution();
            // Always get the latest instruction pointer, as user callbacks may
            // change the value.
            addr = GetInstructionPointer();
            VLOG_INFO(1, "entering tracing state at ", HexStr(addr));
            state_ = TracerState::kTracing;
          } else if (IsInsideCode(addr)) {
            LOG_FATAL("Tracer touches user code at ", HexStr(addr),
                      " before reaching start address ",
                      HexStr(code_start_address_));
          }
        }
        if (state_ == TracerState::kTracing) {
          // BeforeInstruction() is invoked only when addr is pointing to test
          // instructions, and the instruction limit is not reached. In the edge
          // case of empty code, the instruction limit is not reached, and
          // BeforeInstruction() is not invoked.
          if (IsInsideCode(addr) && !stop_requested_) {
            if (++traced_insn_count > max_insn_executed) {
              insn_limit_reached_ = true;
            } else {
              BeforeInstruction();
              addr = GetInstructionPointer();
            }
          }
          if (!IsInsideCode(addr) || stop_requested_) {
            AfterExecution();
            VLOG_INFO(1, "entering finished state at ", HexStr(addr));
            state_ = TracerState::kFinished;
          }
        }
        CHECK(state_ == TracerState::kPreTracing ||
              state_ == TracerState::kTracing ||
              state_ == TracerState::kFinished)
            << absl::StrCat(
                   "Tracer touches user code at ", HexStr(addr),
                   " in an unexpected state: ", static_cast<int>(state_));
        return NextContinuationMode();
      },
      1);
  // Make sure the runner execution was successful.
  RETURN_IF_NOT_OK(run_result.status());
  VLOG_INFO(1, "Native tracer finished tracing with runner execution_result: ",
            run_result->execution_result().DebugString());
  if (!run_result->success()) {
    if (run_result->has_failed_player_result()) {
      switch (run_result->failed_player_result().outcome) {
        // Exclude end state mismatches error.
        case PlaybackOutcome::kAsExpected:
        case PlaybackOutcome::kMemoryMismatch:
        case PlaybackOutcome::kRegisterStateMismatch:
        case PlaybackOutcome::kEndpointMismatch:
          return absl::OkStatus();
        case PlaybackOutcome::kExecutionRunaway:
        case PlaybackOutcome::kExecutionMisbehave:
        default:
          return absl::InternalError("Snapshot did not finish as expected");
      }
    }
    return absl::InternalError("Snapshot failed to run");
  }
  if (insn_limit_reached_) {
    return absl::InternalError("Reached instruction limit.");
  }
  return absl::OkStatus();
}

void NativeTracer::ReadMemory(uint64_t address, void* buffer, size_t size) {}

void NativeTracer::SetRegisters(const UContext<Host>& ucontext) {
  struct user_regs_struct regs;
  SerializeUserRegsStruct(ucontext.gregs, &regs);
  SetGRegs(pid_, regs);
  // TODO(herooutman): set tpidr for ARM.
  // TODO(herooutman): set fpregs.

  // Ptrace may silently discard some bits of the register state.  If this
  // happens, the subsequent GetRegisters() call will return different data.
  // Reset the cache to force a refetch.
  gregs_cache_.reset();
}

void NativeTracer::GetRegisters(UContext<Host>& ucontext) {
  const user_regs_struct& regs = GetGRegStruct();
  // Not all registers will be read. memset so the result is consistent.
  memset(&ucontext.gregs, 0, sizeof(ucontext.gregs));
  DeserializeUserRegsStruct(regs, &ucontext.gregs);
  // TODO(herooutman): get tpidr for ARM.
  // TODO(herooutman): get fpregs.
}

void NativeTracer::SetInstructionPointer(uint64_t address) {
  user_regs_struct regs = GetGRegStruct();
#if defined(__x86_64__)
  regs.rip = address;
  gregs_cache_.value().rip = address;
#elif defined(__aarch64__)
  regs.pc = address;
  gregs_cache_.value().pc = address;
#endif
  SetGRegs(pid_, regs);
}

uint64_t NativeTracer::GetInstructionPointer() {
  return silifuzz::GetInstructionPointer(GetGRegStruct());
}

uint64_t NativeTracer::GetStackPointer() {
#if defined(__x86_64__)
  return GetGRegStruct().rsp;
#elif defined(__aarch64__)
  return GetGRegStruct().sp;
#endif
}

uint32_t NativeTracer::PartialChecksumOfMutableMemory() { return 0; }

const user_regs_struct& NativeTracer::GetGRegStruct() {
  if (!gregs_cache_.has_value()) {
    gregs_cache_.emplace(user_regs_struct{});
    struct iovec io;
    io.iov_base = &gregs_cache_.value();
    io.iov_len = sizeof(gregs_cache_.value());
    // NT_PRSTATUS means read the general purpose registers.
    PTraceOrDie(PTRACE_GETREGSET, pid_, (void*)NT_PRSTATUS, &io);
    CHECK_EQ(io.iov_len, sizeof(gregs_cache_.value()));
  }
  return *gregs_cache_;
}

}  // namespace silifuzz
