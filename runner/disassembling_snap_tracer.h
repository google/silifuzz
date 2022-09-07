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

#ifndef THIRD_PARTY_SILIFUZZ_RUNNER_DISASSEMBLING_SNAP_TRACER_H_
#define THIRD_PARTY_SILIFUZZ_RUNNER_DISASSEMBLING_SNAP_TRACER_H_

#include <sys/types.h>
#include <sys/user.h>

#include <string>
#include <vector>

#include "./common/harness_tracer.h"
#include "./common/snapshot.h"
#include "./player/trace_options.h"

namespace silifuzz {

// SnapMaker::TraceOne()-compatible single-stepper that detects
// non-deterministic instructions and limits the dynamic snapshot length.
//
// This class does not produce any output value. The typical usage is
//
//     DisassemblingSnapTracer tracer(snapshot);
//     auto trace_result_or = <RunnerDriver insn>.TraceOne(
//          snapshot.id(),
//          absl::bind_front(&DisassemblingSnapTracer::Step, &tracer));
//
// DisassemblingSnapTracer will inject a SIGUSR1 as the result of snapshot
// execution if it sees a non-deterministic insn or reaches the insn limit.
// The injected signal will be converted into StatusOr<RunResult>. Currently,
// a Status object will be returned.
//
// This class is thread-compatible.
class DisassemblingSnapTracer {
 public:
  // Represents result of a snapshot tracing.
  struct TraceResult {
    // Number of instructions executed by the snapshot.
    int instructions_executed = 0;

    // Disassembly of the instructions as executed.
    std::vector<std::string> disassembly;

    // Human-readable reason for early snapshot termination if any.
    std::string early_termination_reason;
  };

  // `snapshot` must outlive the instance of DisassemblingSnapTracer.
  DisassemblingSnapTracer(const Snapshot& snapshot)
      : snapshot_(snapshot),
        was_in_snapshot_(false),
        stepper_(snapshot, TraceOptions::Default(), trace_result_) {}

  // Not movable or copyable. Not just a data container.
  DisassemblingSnapTracer(const DisassemblingSnapTracer&) = delete;
  DisassemblingSnapTracer(DisassemblingSnapTracer&&) = delete;
  DisassemblingSnapTracer& operator=(const DisassemblingSnapTracer&) = delete;
  DisassemblingSnapTracer& operator=(DisassemblingSnapTracer&&) = delete;

  // Implements HarnessTracer::Callback interface.
  HarnessTracer::ContinuationMode Step(pid_t pid, const user_regs_struct& regs,
                                       HarnessTracer::CallbackReason reason);

  // Returns result of tracing.
  // NOTE: this can only be safely called after the thread calling Step()
  // has been joined.
  TraceResult trace_result() { return trace_result_; }

 private:
  // Stepper is a stateful implementation for single-stepping one snapshot.
  // StepInstruction() is compatible with HarnessTracer::Callback.
  class SnapshotStepper {
   public:
    // `snapshot` must outlive the instance of Stepper.
    SnapshotStepper(const Snapshot& snapshot, const TraceOptions& options,
                    TraceResult& trace_result)
        : snapshot_(snapshot),
          options_(options),
          prev_instruction_addr_(0),
          prev_instruction_decoding_failed_(false),
          trace_result_(trace_result) {}

    // Not movable or copyable. Not just a data container.
    SnapshotStepper(const SnapshotStepper&) = delete;
    SnapshotStepper(SnapshotStepper&&) = delete;
    SnapshotStepper& operator=(const SnapshotStepper&) = delete;
    SnapshotStepper& operator=(SnapshotStepper&&) = delete;
    ~SnapshotStepper() {}

    // Per-instruction callback invoked by DisassemblingSnapTracer just for the
    // instructions that belong to the snapshot being traced.
    HarnessTracer::ContinuationMode StepInstruction(
        pid_t pid, const struct user_regs_struct& regs,
        HarnessTracer::CallbackReason reason);

   private:
    // The snapshot being traced.
    const Snapshot& snapshot_;

    // Options controlling the tracer's behavior.
    const TraceOptions options_;

    // Address of the previous instruction or 0 when none.
    Snapshot::Address prev_instruction_addr_;

    // Set to indicate that a preceeding insn failed to decode.
    bool prev_instruction_decoding_failed_;

    // Trace result.
    TraceResult& trace_result_;
  };

  TraceResult trace_result_;
  const Snapshot& snapshot_;
  bool was_in_snapshot_;
  SnapshotStepper stepper_;
};

}  // namespace silifuzz
#endif  // THIRD_PARTY_SILIFUZZ_RUNNER_DISASSEMBLING_SNAP_TRACER_H_
