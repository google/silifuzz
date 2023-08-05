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

#ifndef THIRD_PARTY_SILIFUZZ_TRACING_UNICORN_TRACER_H_
#define THIRD_PARTY_SILIFUZZ_TRACING_UNICORN_TRACER_H_

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./common/proxy_config.h"
#include "./common/raw_insns_util.h"
#include "./common/snapshot.h"
#include "./common/snapshot_util.h"
#include "./tracing/unicorn_util.h"
#include "./util/checks.h"
#include "./util/ucontext/ucontext.h"
#include "third_party/unicorn/unicorn.h"

namespace silifuzz {

// An architecture-generic class for executing code snippets in Unicorn.
// This class is not thread safe.  Each thread should have its own instance.
// Note: this header includes some non-trivial functions. This isn't ideal, but
// since this a templated class, moving them out of line requires explicitly
// instantiating them for each arch. Explicitly instantiating them for each arch
// has consequences for the linker, particularly because we're trying to let the
// user link in only the arch support they need to simplify coverage reports.
template <typename Arch>
class UnicornTracer {
 public:
  UnicornTracer() : uc_(nullptr), start_of_code_(0), end_of_code_(0) {}
  ~UnicornTracer() { Destroy(); }

  void Destroy() {
    if (uc_ != nullptr) {
      uc_close(uc_);
      uc_ = nullptr;
    }
  }

  // Prepare Unicorn to run a code snippet.
  absl::Status InitSnippet(absl::string_view instructions,
                           const FuzzingConfig<Arch>& fuzzing_config =
                               DEFAULT_FUZZING_CONFIG<Arch>) {
    ASSIGN_OR_RETURN_IF_NOT_OK(
        Snapshot snapshot,
        InstructionsToSnapshot<Arch>(instructions, fuzzing_config));

    UContext<Arch> ucontext;
    absl::Status status = ConvertRegsFromSnapshot(
        snapshot.registers(), &ucontext.gregs, &ucontext.fpregs);
    if (!status.ok()) {
      LOG_FATAL("Failed to deserialize registers - ", status.message());
    }

    InitUnicorn();

    SetupSnippetMemory(snapshot, ucontext, fuzzing_config);

    SetInitialRegisters(ucontext);

    start_of_code_ = GetCurrentInstructionPointer();
    end_of_code_ = GetExitPoint(snapshot);

    return absl::OkStatus();
  }

  using InstructionCallback = void(UnicornTracer<Arch>* tracer,
                                   uint64_t address, uint32_t size);

  // Ask the tracer to invoke `callback` before each instruction is executed.
  // F should be compatible with InstructionCallback.
  // This method should not be called more than once.
  template <typename F>
  void SetInstructionCallback(F&& callback) {
    CHECK(!instruction_callback_);
    instruction_callback_ = callback;
    UNICORN_CHECK(uc_hook_add(uc_, &hook_code_, UC_HOOK_CODE,
                              (void*)&DispatchHookCode, this, start_of_code_,
                              end_of_code_));
  }

  // Run the code snippet. Execution will stop after `max_insn_executed`
  // instructions to help avoid infinite loops.
  absl::Status Run(size_t max_insn_executed) {
    num_instructions_ = 0;
    max_instructions_ = max_insn_executed;
    should_be_stopped_ = false;

    // Unicorn can hang due to bugs in QEMU.
    // Halt execution if it exceeds 1 seconds of wall clock time.
    // This value is arbitrary and may need to be tuned.
    // We don't want this value to be so small that machine load can easily
    // cause the deadline to be missed.
    // We don't want this value to be so large that fault injection will take
    // forever when we hit a degenerate case.
    // Empirically, 1 second is about 20x-30x longer than execution takes in the
    // worst case on an unloaded machine.
    uint64_t timeout_microseconds = 1000000;
    uc_err err = uc_emu_start(uc_, start_of_code_, end_of_code_,
                              timeout_microseconds, max_insn_executed);

    // Check if the emulator stopped cleanly.
    if (err) {
      return absl::InternalError(absl::StrCat(
          "uc_emu_start() returned ", IntStr(err), ": ", uc_strerror(err)));
    }

    if (num_instructions_ > max_insn_executed) {
      // QEMU x86_64 may not always respect max_insn_executed.
      return absl::InternalError("emulator executed too many instructions");
    }

    // Check if the timeout fired.
    size_t result;
    UNICORN_CHECK(uc_query(uc_, UC_QUERY_TIMEOUT, &result));
    if (result) {
      return absl::InternalError("execution timed out");
    }

    // Check if the emulator stopped at the right address.
    // Unicorn does not return an error if it stops executing because it reached
    // the maximum instruction count.
    uint64_t pc = GetCurrentInstructionPointer();
    if (pc != end_of_code_) {
      return absl::InternalError("execution did not reach end of code snippet");
    }

    RETURN_IF_NOT_OK(ValidateArchEndState());

    return absl::OkStatus();
  }

  // Should only be invoked inside callbacks from Run()
  void Stop() {
    uc_emu_stop(uc_);
    should_be_stopped_ = true;
  }

  uint64_t GetCurrentInstructionPointer();
  void SetCurrentInstructionPointer(uint64_t address);

  uint64_t GetCurrentStackPointer();

  // Read the current register state. Not all platforms can read all registers,
  // so some registers may be set to zero instead of their actual values.
  void GetRegisters(UContext<Arch>& ucontext);

  // Write the current register state. Not all platforms can write all
  // registers, so some registers may not be updated.
  void SetRegisters(const UContext<Arch>& ucontext);

  void ReadMemory(uint64_t address, void* buffer, size_t size) {
    UNICORN_CHECK(uc_mem_read(uc_, address, buffer, size));
  }

 private:
  // Initialize Unicorn and put it in a state that it can execute code snippets
  // and Snapshots. This may involve setting system registers, etc.
  void InitUnicorn();

  // Setup the memory mappings and memory contents for a snippet that has been
  // turned into a Snapshot with InstructionsToSnapshot.
  void SetupSnippetMemory(const Snapshot& snapshot,
                          const UContext<Arch>& ucontext,
                          const FuzzingConfig<Arch>& fuzzing_config);

  // Set Unicorn's architectural state. The Unicorn API may not give access to
  // setting all the state that we want, so this function may execute arbitrary
  // instructions. For this reason, the method will only be called during init.
  void SetInitialRegisters(const UContext<Arch>& ucontext);

  // Check that the arch-specific architectural state is acceptable after the
  // instructions are done executing. Unicorn may not catch all this issues that
  // will prevent turning this into a valid Snapshot.
  absl::Status ValidateArchEndState();

  void HookCode(uint64_t address, uint32_t size) {
    // If Stop() has been called, we suppress further callbacks. Unicorn may not
    // stop immediately.
    if (!should_be_stopped_) {
      if (num_instructions_ >= max_instructions_) {
        // QEMU x86_64 may not always respect max_insn_executed.
        // We don't invoke the callback in this case so that clients can behave
        // as if the limit works.
        Stop();
      } else {
        // On x86, Unicorn will sometimes invoke this function with an invalid
        // max_size when it has absolutely no idea what the instruction does.
        // (AVX512 for example.) It appears to be some sort of error code gone
        // wrong? All instructions should be 15 bytes or less.
        size = std::min(size, 15U);

        // Unicorn knows the exact size of the instruction, but other tracers
        // may not so we treat "size" as a maximum size for the instruction,
        // which happens to be exact for this particular tracer.
        instruction_callback_(this, address, size);
      }
    }
    num_instructions_++;
  }

  static void DispatchHookCode(uc_engine* uc, uint64_t address, uint32_t size,
                               void* user_data) {
    UnicornTracer<Arch>* tracer = static_cast<UnicornTracer<Arch>*>(user_data);
    tracer->HookCode(address, size);
  }

  uc_engine* uc_;

  uint64_t start_of_code_;
  uint64_t end_of_code_;

  uc_hook hook_code_;

  size_t num_instructions_;
  size_t max_instructions_;
  bool should_be_stopped_;

  std::function<InstructionCallback> instruction_callback_;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_TRACING_UNICORN_TRACER_H_
