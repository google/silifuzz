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

#ifndef THIRD_PARTY_SILIFUZZ_TRACING_TRACER_H_
#define THIRD_PARTY_SILIFUZZ_TRACING_TRACER_H_

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "./common/proxy_config.h"
#include "./util/arch.h"
#include "./util/checks.h"
#include "./util/reg_group_io.h"
#include "./util/ucontext/ucontext_types.h"

namespace silifuzz {

template <typename Arch>
struct TracerConfig {};

template <>
struct TracerConfig<X86_64> {
  // If true, the tracer will enforce the fuzzing config when making snapshots.
  // This should be set to true for fuzzing.
  bool enforce_fuzzing_config = false;
};

template <>
struct TracerConfig<AArch64> {
  // Force Unicorn to emulate a A72 processor.
  // This is a bit old, but if used as a fuzz target the resulting tests should
  // be compatible with most hardware you would want to run on.
  // By default Unicorn is roughly a A77+, it support sha512, sm3, and sm4.
  bool unicorn_force_a72 = false;
  // If true, the tracer will enforce the fuzzing config when making snapshots.
  // This should be set to true for fuzzing.
  bool enforce_fuzzing_config = false;
};

// TracerControl is a helper class for Tracer. It provides a way to access
// Tracer's private methods from user callbacks.
template <typename Arch>
class TracerControl;

// The base architecture-generic tracer class for executing code snippets. It
// defines three entry points for user to interact with tracee during the
// execution:
// 1. BeforeExecution: invoked before the test is executed.
// 2. BeforeInstruction: invoked before each instruction is executed. In the
// case of the first instruction, this callback is invoked right after the
// BeforeExecution callback.
// 3. AfterExecution: invoked after the test is executed.
//
// BeforeExecution() and AfterExecution() are necessary for tracers (e.g.
// NativeTracer) that rely on silifuzz runner to execute tests. They should be
// invoked right at the runner jumps into/out of the test code region to get
// accurate initial/final state of the test.
//
// User can register callbacks via the setters, and each setter can be called
// at most once.
template <typename Arch>
class Tracer {
 public:
  using UserCallback = std::function<void(TracerControl<Arch>& tracer)>;
  Tracer<Arch>() {
    tracer_control_ =
        std::unique_ptr<TracerControl<Arch>>(new TracerControl<Arch>(*this));
  };
  virtual ~Tracer() = default;

  // Initialize the tracer with a snippet of code.
  virtual absl::Status InitSnippet(
      absl::string_view instructions,
      const TracerConfig<Arch>& tracer_config = TracerConfig<Arch>{},
      const FuzzingConfig<Arch>& fuzzing_config =
          DEFAULT_FUZZING_CONFIG<Arch>) = 0;

  // Run the code snippet. Execution will stop after `max_insn_executed`
  // instructions to help avoid infinite loops.
  virtual absl::Status Run(size_t max_insn_executed) = 0;

  // Callback registration
  void SetBeforeExecutionCallback(UserCallback callback) {
    if (before_execution_callback_) {
      LOG_FATAL("BeforeExecution callback already set");
    }
    before_execution_callback_ = std::move(callback);
  }
  void SetBeforeInstructionCallback(UserCallback callback) {
    if (before_instruction_callback_) {
      LOG_FATAL("BeforeInstruction callback already set");
    }
    before_instruction_callback_ = std::move(callback);
  }
  void SetAfterExecutionCallback(UserCallback callback) {
    if (after_execution_callback_) {
      LOG_FATAL("AfterExecution callback already set");
    }
    after_execution_callback_ = std::move(callback);
  }

  friend class TracerControl<Arch>;

 protected:
  // Tracer control methods.
  // Request the tracer to stop. The implementation and behavior are tracer
  // dependent. Unicorn tracer stops the emulation and hence code execution
  // immediately, while native tracer only stops tracing, but continues to
  // execute the code.
  virtual void Stop() = 0;
  virtual void SetInstructionPointer(uint64_t address) = 0;
  // Write the current register state. Not all platforms can write all
  // registers, so some registers may not be updated.
  virtual void SetRegisters(const UContext<Arch>& ucontext) = 0;

  // Accessors
  virtual uint64_t GetInstructionPointer() = 0;
  virtual uint64_t GetStackPointer() = 0;
  // Read a continuous chunk of memory of `size` bytes starting from the
  // `address`, and store the result in `buffer`. The buffer needs to be large
  // enough to hold the requested `size` bytes. If the read touches invalid or
  // inaccessible memory (e.g unmapped or protected), a fatal error will be
  // raised.
  virtual void ReadMemory(uint64_t address, void* buffer, size_t size) = 0;
  // Read the current register state of the tracee. GPR and FP registers are
  // always read and stored in `ucontext`. If `eregs` is not null, the extension
  // registers are also read and stored in `eregs`.
  virtual void GetRegisters(UContext<Arch>& ucontext,
                            RegisterGroupIOBuffer<Arch>* eregs) = 0;
  // Checksum some of the tracer's mutable memory.
  // This function does not checksum all the mutable memory because this can be
  // quite slow for the x86_64 which has ~1GB of mutable memory.
  // This checksum can be used by fault injection to quickly estimate if the end
  // state is different than expected.
  // The exact definition of this checksum may change over time, comparing a
  // value produced by an old version of the software against a value produced
  // by a new version of the software is not meaningful.
  virtual uint32_t PartialChecksumOfMutableMemory() = 0;
  uint64_t GetCodeStartAddress() const { return code_start_address_; }

  // Callback invocation
  void BeforeExecution() {
    if (before_execution_callback_) {
      before_execution_callback_(*tracer_control_);
    }
  }
  void BeforeInstruction() {
    if (before_instruction_callback_) {
      before_instruction_callback_(*tracer_control_);
    }
  }
  void AfterExecution() {
    if (after_execution_callback_) {
      after_execution_callback_(*tracer_control_);
    }
  }

  // Helper functions
  // Returns true if the address is inside the code snippet.
  inline bool IsInsideCode(uint64_t address) const {
    return code_start_address_ <= address && address < code_end_address_;
  }

  // Check if an instruction that dangles past the end of code is executed. This
  // can happens on X86 if the fuzzing input ends with a partial instruction
  // that depends on the bytes that come after the test.
  inline bool InstructionIsInRange(uint64_t address, size_t size) const {
    return address >= code_start_address_ &&
           address + size <= code_end_address_;
  }

  uint64_t code_start_address_;
  uint64_t code_end_address_;

  bool should_be_stopped_ = false;

  size_t num_instructions_;
  size_t max_instructions_;

 private:
  Tracer<Arch>::UserCallback before_execution_callback_;
  Tracer<Arch>::UserCallback before_instruction_callback_;
  Tracer<Arch>::UserCallback after_execution_callback_;

  std::unique_ptr<TracerControl<Arch>> tracer_control_;
};

// TracerControl is a helper class for Tracer. It provides a way to access
// Tracer's private methods from user callbacks.
template <typename Arch>
class TracerControl {
 public:
  // Not copyable or movable.
  TracerControl(const TracerControl&) = delete;
  TracerControl(TracerControl&&) = delete;
  TracerControl& operator=(const TracerControl&) = delete;
  TracerControl& operator=(TracerControl&&) = delete;

  inline void Stop() { tracer_.Stop(); }
  inline void SetInstructionPointer(uint64_t address) {
    tracer_.SetInstructionPointer(address);
  }
  inline void SetRegisters(const UContext<Arch>& ucontext) {
    tracer_.SetRegisters(ucontext);
  }
  inline uint64_t GetInstructionPointer() {
    return tracer_.GetInstructionPointer();
  }
  inline uint64_t GetStackPointer() { return tracer_.GetStackPointer(); }
  inline void ReadMemory(uint64_t address, void* buffer, size_t size) {
    tracer_.ReadMemory(address, buffer, size);
  }
  inline void GetRegisters(UContext<Arch>& ucontext,
                           RegisterGroupIOBuffer<Arch>* eregs = nullptr) {
    tracer_.GetRegisters(ucontext, eregs);
  }
  inline uint32_t PartialChecksumOfMutableMemory() {
    return tracer_.PartialChecksumOfMutableMemory();
  }
  inline uint64_t GetCodeStartAddress() {
    return tracer_.GetCodeStartAddress();
  }
  inline bool IsInsideCode(uint64_t address) {
    return tracer_.IsInsideCode(address);
  }
  inline bool InstructionIsInRange(uint64_t address, size_t size) {
    return tracer_.InstructionIsInRange(address, size);
  }
  friend class Tracer<Arch>;

 private:
  TracerControl<Arch>(Tracer<Arch>& tracer) : tracer_(tracer) {}
  Tracer<Arch>& tracer_;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_TRACING_TRACER_H_
