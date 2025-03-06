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
#include <sys/types.h>
#include <sys/user.h>

#include <cstddef>
#include <cstdint>
#include <memory>

#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "./common/harness_tracer.h"
#include "./common/proxy_config.h"
#include "./common/snapshot.h"
#include "./tracing/tracer.h"
#include "./util/arch.h"
#include "./util/checks.h"
#include "./util/ucontext/ucontext_types.h"

namespace silifuzz {

class NativeTracer final : public Tracer<Host> {
 public:
  NativeTracer() {};
  absl::Status InitSnippet(
      absl::string_view instructions,
      const TracerConfig<Host>& tracer_config = TracerConfig<Host>{},
      const FuzzingConfig<Host>& fuzzing_config =
          DEFAULT_FUZZING_CONFIG<Host>) override;

  absl::Status Run(size_t max_insn_executed) override;

  void Stop() override { stop_requested_ = true; }
  void SetInstructionPointer(uint64_t address) override;
  void SetRegisters(const UContext<Host>& ucontext) override;

  uint64_t GetInstructionPointer() override;
  uint64_t GetStackPointer() override;
  void ReadMemory(uint64_t address, void* buffer, size_t size) override;
  void GetRegisters(UContext<Host>& ucontext) override;
  uint32_t PartialChecksumOfMutableMemory() override;

 private:
  enum class TracerState {
    kInit,        // the default state when created
    kReady,       // tracer is initialized and ready to run
    kPreTracing,  // Run() has been called, but not yet reached the input code
    kTracing,     // tracer is running and reached the input code
    kFinished,    // tracer reached the end of the input code
  };
  inline bool ShouldStopTracing() {
    return state_ == TracerState::kFinished || stop_requested_ ||
           insn_limit_reached_;
  }
  inline HarnessTracer::ContinuationMode NextContinuationMode() {
    return ShouldStopTracing() ? HarnessTracer::kStopTracing
                               : HarnessTracer::kKeepTracing;
  }

  TracerState state_ = TracerState::kInit;
  std::unique_ptr<Snapshot> snapshot_ = nullptr;
  pid_t pid_ = 0;  // pid of the tracee
  bool stop_requested_ = false;
  bool insn_limit_reached_ = false;
};
}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_TRACING_NATIVE_TRACER_H_
