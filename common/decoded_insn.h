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

#ifndef THIRD_PARTY_SILIFUZZ_COMMON_DECODED_INSN_H_
#define THIRD_PARTY_SILIFUZZ_COMMON_DECODED_INSN_H_

#include <sys/user.h>

#include "absl/status/status.h"
#include "./common/snapshot.h"
#include "./util/checks.h"

extern "C" {
#include "third_party/libxed/xed-interface.h"
};

namespace silifuzz {

// Represents a single decoded x86_64 instruction.
//
// Users must consult is_valid() before calling any accessors.
// This class is thread-compatible.
class DecodedInsn {
 public:
  // Constructs an instance from MemoryBytes.
  explicit DecodedInsn(const Snapshot::MemoryBytes& data);

  // Constructs an instance from a string-like object.
  explicit DecodedInsn(absl::string_view data);

  // Default movable and copyable.

  // Tells if this instruction represents a valid instruction according to the
  // disassembly engine.
  bool is_valid() const { return status_.ok(); }

  // Tells if the instruction is deterministic.
  //
  // NOTE: the definition of "deterministic" is somewhat fuzzy in this context.
  // We consider an insn non-deterministic if its behavior depends on any state
  // that is not captured by the Snapshot data structure or whos behavior varies
  // across various production and corp platforms.
  // REQUIRES: is_valid().
  bool is_deterministic() const;

  // Tells if the instruction locks memory. An instruction locks memory if
  // it 1) has at least 1 memory operand and
  //    2) has a valid lock prefix (e.g. lock add) or
  //       it is the XCHG instruction, which does not require a lock prefix.
  // REQUIRES: is_valid().
  bool is_locking() const;

  // Tells if executing the instruction with register values in `regs` may
  // create a split-lock that crosses a cache line boundary. This is a
  // best-effort estimate. The decision is made using the effective address
  // only. If the address cannot be accessed in runtime, a page fault or a
  // general protection fault will prevent a split-lock even if
  // may_have_split_lock() returns true. The effective address computation is
  // as accurate as the underlying XED library. If an instruction cannot be
  // decoded by XED. This function cannot be used at all. If address computation
  // fails internally in XED, this return false. So this can have false
  // negatives in theory.
  // REQUIRES: is_valid().
  bool may_have_split_lock(const struct user_regs_struct& regs);

  // Returns textual representation of the instruction in Intel syntax.
  // REQUIRES: is_valid().
  absl::string_view DebugString() const {
    DCHECK_STATUS(status_);
    return formatted_insn_buf_;
  }

  // Returns the length of the instruction in bytes.
  // REQUIRES: is_valid().
  size_t length() const {
    DCHECK_STATUS(status_);
    return xed_decoded_inst_get_length(&xed_insn_);
  }

  // Returns instruction mnemonic.
  // REQUIRES: is_valid().
  std::string mnemonic() const;

  // Constructs an instance of DecodedInsn from a live process.
  // `pid` must identify a process that is in a ptrace-stopped state.
  // `addr` is the address of the first byte.
  //
  // RETURNS: error if there was a problem fetching bytes from the process.
  // DecodedInsn otherwise. Caller still need to consule is_valid() before
  // using the returned instance.
  static absl::StatusOr<DecodedInsn> FromLiveProcess(pid_t pid,
                                                     Snapshot::Address addr) {
    absl::StatusOr<Snapshot::MemoryBytes> data = FetchInstruction(pid, addr);
    RETURN_IF_NOT_OK(data.status());
    return DecodedInsn(data.value());
  }

 private:
  friend class DecodedInsnTestPeer;

  absl::Status Decode(absl::string_view data, uint64_t start_address = 0x0);

  // Fetches up to 16 bytes starting at `addr` from the ptrace-stopped process
  // identified by `pid`.
  static absl::StatusOr<Snapshot::MemoryBytes> FetchInstruction(
      pid_t pid, Snapshot::Address addr);

  // Helper function for address generation using XED.
  // Returns a 64-bit zero-extended value of `reg` from `regs` or an error.
  static absl::StatusOr<uint64_t> get_reg(xed_reg_enum_t reg,
                                          const struct user_regs_struct& regs);

  // XED agen register callback. `context` must be a user_regs_struct pointer.
  static xed_uint64_t agen_reg_callback(xed_reg_enum_t reg, void* context,
                                        xed_bool_t* error);

  // XED agen segment callback. `context` must be a user_regs_struct pointer.
  static xed_uint64_t agen_segment_callback(xed_reg_enum_t reg, void* context,
                                            xed_bool_t* error);

  // Returns the address of the `i-th` memory operand of this instruction
  // using register values in `regs` or returns an error.
  // REQUIRES: is_valid() and i < number of memory operands.
  absl::StatusOr<uint64_t> memory_operand_address(
      size_t i, const struct user_regs_struct& regs);

  // The decoded insn.
  xed_decoded_inst_t xed_insn_;

  // Decoding error if any.
  absl::Status status_;

  // Text-formatted insn. See DebugString()
  char formatted_insn_buf_[64];
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_COMMON_DECODED_INSN_H_
