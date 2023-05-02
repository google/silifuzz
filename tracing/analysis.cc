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

#include "./tracing/unicorn_tracer.h"
#include "./util/arch.h"
#include "./util/checks.h"
#include "./util/ucontext/ucontext.h"

namespace silifuzz {

namespace {

// An extremely simple fault model is to skip a specific instruction in the
// trace. All you need to know is the size of the instruction, and you don't
// need to model its side effects.
template <typename Arch>
absl::Status TraceSnippetWithSkip(const std::string& instructions,
                                  size_t max_instructions, size_t skip,
                                  size_t& instructions_executed,
                                  UContext<Arch>& ucontext) {
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
  return absl::OkStatus();
}

}  // namespace

template <typename Arch>
absl::StatusOr<FaultInjectionResult> AnalyzeSnippetWithFaultInjection(
    const std::string& instructions, size_t max_instructions) {
  size_t base_instructions_executed = 0;
  UContext<Arch> base_ucontext;
  RETURN_IF_NOT_OK(TraceSnippetWithSkip(instructions, max_instructions, ~0,
                                        base_instructions_executed,
                                        base_ucontext));

  size_t detected = 0;
  for (size_t skip = 0; skip < base_instructions_executed; ++skip) {
    if (skip % 100 == 0) {
      VLOG_INFO(1, 100 * skip / base_instructions_executed, "%");
    }
    size_t instructions_executed = 0;
    UContext<Arch> ucontext;
    absl::Status status = TraceSnippetWithSkip(
        instructions, max_instructions, skip, instructions_executed, ucontext);
    // If the status is not OK, this indicates the trace did not behave like a
    // valid Silifuzz test - it segfaulted, got stuck in an infinite loop, or
    // similar. Because the unmodified trace as OK, this indicates the injected
    // fault changed the behavior in a detectible way.
    // TODO(ncbray): compare memory.
    if (!status.ok() || ucontext.gregs != base_ucontext.gregs ||
        ucontext.fpregs != base_ucontext.fpregs) {
      detected++;
    }
  }
  return FaultInjectionResult{
      .instruction_count = base_instructions_executed,
      .fault_injection_count = base_instructions_executed,
      .fault_detection_count = detected,
      .sensitivity = static_cast<float>(detected) /
                     std::max(base_instructions_executed, 1UL),
  };
}

// Instantiate concrete instances of exported functions.
template absl::StatusOr<FaultInjectionResult>
AnalyzeSnippetWithFaultInjection<X86_64>(const std::string& instructions,
                                         size_t max_instructions);
template absl::StatusOr<FaultInjectionResult>
AnalyzeSnippetWithFaultInjection<AArch64>(const std::string& instructions,
                                          size_t max_instructions);

}  // namespace silifuzz
