// Copyright 2023 The SiliFuzz Authors.
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

#include "./tracing/analysis.h"

#include <algorithm>
#include <cstdint>
#include <string>

#include "absl/status/status.h"
#include "./tracing/execution_trace.h"
#include "./tracing/unicorn_tracer.h"
#include "./util/checks.h"
#include "./util/ucontext/ucontext_types.h"

namespace silifuzz {

namespace {

// An extremely simple fault model is to skip a specific instruction in the
// trace. All you need to know is the size of the instruction, and you don't
// need to model its side effects.
template <typename Arch>
absl::Status TraceSnippetWithSkip(const std::string& instructions,
                                  size_t max_instructions, size_t skip,
                                  size_t& instructions_executed,
                                  UContext<Arch>& ucontext,
                                  uint32_t& memory_checksum) {
  UnicornTracer<Arch> tracer;
  RETURN_IF_NOT_OK(tracer.InitSnippet(instructions));

  instructions_executed = 0;
  tracer.SetInstructionCallback(
      [&](UnicornTracer<Arch>* tracer, uint64_t address, size_t max_size) {
        if (instructions_executed == skip) {
          // Relies on the instruction size for Unicorn being precise.
          // For ptrace we'll need to disassemble the instruction.
          tracer->SetCurrentInstructionPointer(address + max_size);
        }
        instructions_executed++;
      });
  RETURN_IF_NOT_OK(tracer.Run(max_instructions));
  tracer.GetRegisters(ucontext);
  memory_checksum = tracer.PartialChecksumOfMutableMemory();
  return absl::OkStatus();
}

}  // namespace

template <typename Arch>
absl::StatusOr<FaultInjectionResult> AnalyzeSnippetWithFaultInjection(
    const std::string& instructions, ExecutionTrace<Arch>& execution_trace,
    uint32_t expected_memory_checksum) {
  size_t expected_instructions_executed = execution_trace.NumInstructions();
  UContext<Arch> expected_ucontext = execution_trace.LastContext();

  // See if skipping an instruction results in a different outcome.
  size_t num_faults_detected = 0;
  for (size_t skip = 0; skip < expected_instructions_executed; ++skip) {
    if (skip % 100 == 0) {
      VLOG_INFO(1, 100 * skip / expected_instructions_executed, "%");
    }
    size_t instructions_executed = 0;
    uint32_t actual_memory_checksum = 0;
    UContext<Arch> ucontext;
    absl::Status status = TraceSnippetWithSkip(
        instructions, execution_trace.MaxInstructions(), skip,
        instructions_executed, ucontext, actual_memory_checksum);
    // If the status is not OK, this indicates the trace did not behave like a
    // valid Silifuzz test - it segfaulted, got stuck in an infinite loop, or
    // similar. Because the unmodified trace as OK, this indicates the injected
    // fault changed the behavior in a detectible way.
    // TODO(ncbray): compare memory.
    bool fault_detected = !status.ok() ||
                          ucontext.gregs != expected_ucontext.gregs ||
                          ucontext.fpregs != expected_ucontext.fpregs ||
                          actual_memory_checksum != expected_memory_checksum;
    execution_trace.Info(skip).critical = fault_detected;
    if (fault_detected) {
      num_faults_detected++;
    }
  }
  return FaultInjectionResult{
      .instruction_count = expected_instructions_executed,
      .fault_injection_count = expected_instructions_executed,
      .fault_detection_count = num_faults_detected,
      .sensitivity = static_cast<float>(num_faults_detected) /
                     std::max(expected_instructions_executed, 1UL),
  };
}

// Instantiate concrete instances of exported functions.
template absl::StatusOr<FaultInjectionResult>
AnalyzeSnippetWithFaultInjection<X86_64>(
    const std::string& instructions, ExecutionTrace<X86_64>& execution_trace,
    uint32_t expected_memory_checksum);
template absl::StatusOr<FaultInjectionResult>
AnalyzeSnippetWithFaultInjection<AArch64>(
    const std::string& instructions, ExecutionTrace<AArch64>& execution_trace,
    uint32_t expected_memory_checksum);

}  // namespace silifuzz
