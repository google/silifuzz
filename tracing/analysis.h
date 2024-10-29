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

#ifndef THIRD_PARTY_SILIFUZZ_TRACING_ANALYSIS_H_
#define THIRD_PARTY_SILIFUZZ_TRACING_ANALYSIS_H_

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

#include "absl/status/statusor.h"
#include "./instruction/disassembler.h"
#include "./tracing/execution_trace.h"

namespace silifuzz {

struct FaultInjectionResult {
  size_t instruction_count;
  size_t fault_injection_count;
  size_t fault_detection_count;
  float sensitivity;
};

// Perform fault analysis on the snippet `instructions`.
// `execution_trace` must contain a valid trace. If this function is successful,
// the trace is annotated with which instructions were critical in detecting
// faults.
// If successful, this function returns aggregate statistics about the fault
// injection.
template <typename Arch>
absl::StatusOr<FaultInjectionResult> AnalyzeSnippetWithFaultInjection(
    const std::string& instructions, ExecutionTrace<Arch>& execution_trace,
    uint32_t expected_memory_checksum);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_TRACING_ANALYSIS_H_
