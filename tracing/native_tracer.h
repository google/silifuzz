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

#ifndef THIRD_PARTY_SILIFUZZ_TRACING_NATIVE_TRACER_H_
#define THIRD_PARTY_SILIFUZZ_TRACING_NATIVE_TRACER_H_

#include <linux/elf.h>

#include <cstddef>
#include <cstdint>

#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "./common/proxy_config.h"
#include "./tracing/tracer.h"
#include "./util/arch.h"
#include "./util/checks.h"
#include "./util/ucontext/ucontext_types.h"

namespace silifuzz {

class NativeTracer final : public Tracer<Host> {
 public:
  absl::Status InitSnippet(
      absl::string_view instructions,
      const TracerConfig<Host>& tracer_config = TracerConfig<Host>{},
      const FuzzingConfig<Host>& fuzzing_config =
          DEFAULT_FUZZING_CONFIG<Host>) override;

  absl::Status Run(size_t max_insn_executed) override;

  void Stop() override;
  void SetInstructionPointer(uint64_t address) override;
  void SetRegisters(const UContext<Host>& ucontext) override;

  uint64_t GetInstructionPointer() override;
  uint64_t GetStackPointer() override;
  void ReadMemory(uint64_t address, void* buffer, size_t size) override;
  void GetRegisters(UContext<Host>& ucontext) override;
  uint32_t PartialChecksumOfMutableMemory() override;
};
}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_TRACING_NATIVE_TRACER_H_
