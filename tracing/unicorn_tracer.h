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

#ifndef THIRD_PARTY_SILIFUZZ_PROXIES_UNICORN_TRACER_H_
#define THIRD_PARTY_SILIFUZZ_PROXIES_UNICORN_TRACER_H_

#include <cstddef>
#include <cstdint>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "./common/proxy_config.h"
#include "./common/raw_insns_util.h"
#include "./common/snapshot.h"
#include "./common/snapshot_util.h"
#include "./tracing/unicorn_util.h"
#include "./util/ucontext/ucontext.h"
#include "third_party/unicorn/unicorn.h"

namespace silifuzz {

// An architecture-generic class for executing code snippets in Unicorn.
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
                           const FuzzingConfig<Arch>& fuzzing_config) {
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

  // Run the code snippet. Execution will stop after `max_insn_executed`
  // instructions to help avoid infinite loops.
  absl::Status Run(size_t max_insn_executed) {
    uc_err err =
        uc_emu_start(uc_, start_of_code_, end_of_code_, 0, max_insn_executed);

    // Check if the emulator stopped cleanly.
    if (err) {
      return absl::InternalError(absl::StrCat(
          "uc_emu_start() returned ", IntStr(err), ": ", uc_strerror(err)));
    }

    // Check if the emulator stopped at the right address.
    // Unicorn does not return an error if it stops executing because it reached
    // the maximum instruction count.
    uint64_t pc = GetCurrentInstructionPointer();
    if (pc != end_of_code_) {
      return absl::InternalError(
          absl::StrCat("expected PC would be ", HexStr(end_of_code_),
                       ", but got ", HexStr(pc), " instead"));
    }

    RETURN_IF_NOT_OK(ValidateArchEndState());

    return absl::OkStatus();
  }

  uint64_t GetCurrentInstructionPointer();
  uint64_t GetCurrentStackPointer();

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

  uc_engine* uc_;

  uint64_t start_of_code_;
  uint64_t end_of_code_;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_PROXIES_UNICORN_TRACER_H_
