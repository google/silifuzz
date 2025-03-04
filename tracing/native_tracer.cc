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

#include <cstddef>
#include <cstdint>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "./common/proxy_config.h"
#include "./tracing/tracer.h"
#include "./util/arch.h"
#include "./util/ucontext/ucontext_types.h"

namespace silifuzz {

absl::Status NativeTracer::InitSnippet(
    absl::string_view instructions, const TracerConfig<Host>& tracer_config,
    const FuzzingConfig<Host>& fuzzing_config) {
  return absl::UnimplementedError("InitSnippet() not implemented");
};

absl::Status NativeTracer::Run(size_t max_insn_executed) {
  return absl::UnimplementedError("Run() not implemented");
}
void NativeTracer::Stop() {}
void NativeTracer::ReadMemory(uint64_t address, void* buffer, size_t size) {}

void NativeTracer::SetRegisters(const UContext<Host>& ucontext) {}

void NativeTracer::GetRegisters(UContext<Host>& ucontext) {}

void NativeTracer::SetInstructionPointer(uint64_t address) {}

uint64_t NativeTracer::GetInstructionPointer() { return 0; }

uint64_t NativeTracer::GetStackPointer() { return 0; }

uint32_t NativeTracer::PartialChecksumOfMutableMemory() { return 0; }

}  // namespace silifuzz
