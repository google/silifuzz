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

#include "./common/snapshot_util.h"

#include <stddef.h>

#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "./common/snapshot.h"
#include "./util/checks.h"
#include "./util/ucontext/serialize.h"

namespace silifuzz {

template <typename Arch>
Snapshot::RegisterState ConvertRegsToSnapshot(const GRegSet<Arch>& gregs,
                                              const FPRegSet<Arch>& fpregs) {
  Snapshot::ByteData gregs_bytes, fpregs_bytes;
  CHECK(SerializeGRegs(gregs, &gregs_bytes));
  CHECK(SerializeFPRegs(fpregs, &fpregs_bytes));
  return Snapshot::RegisterState(gregs_bytes, fpregs_bytes);
}

template Snapshot::RegisterState ConvertRegsToSnapshot(
    const GRegSet<X86_64>& gregs, const FPRegSet<X86_64>& fpregs);
template Snapshot::RegisterState ConvertRegsToSnapshot(
    const GRegSet<AArch64>& gregs, const FPRegSet<AArch64>& fpregs);

template <typename Arch>
absl::Status ConvertRegsFromSnapshot(
    const Snapshot::RegisterState& register_state, GRegSet<Arch>* gregs) {
  if (!DeserializeGRegs(register_state.gregs(), gregs)) {
    return absl::InvalidArgumentError("Failed to deserialize gregs");
  }
  return absl::OkStatus();
}

template absl::Status ConvertRegsFromSnapshot(
    const Snapshot::RegisterState& register_state, GRegSet<X86_64>* gregs);
template absl::Status ConvertRegsFromSnapshot(
    const Snapshot::RegisterState& register_state, GRegSet<AArch64>* gregs);

template <typename Arch>
absl::Status ConvertRegsFromSnapshot(
    const Snapshot::RegisterState& register_state, GRegSet<Arch>* gregs,
    FPRegSet<Arch>* fpregs) {
  RETURN_IF_NOT_OK(ConvertRegsFromSnapshot(register_state, gregs));
  if (!DeserializeFPRegs(register_state.fpregs(), fpregs)) {
    return absl::InvalidArgumentError("Failed to deserialize fpregs");
  }
  return absl::OkStatus();
}

template absl::Status ConvertRegsFromSnapshot(
    const Snapshot::RegisterState& register_state, GRegSet<X86_64>* gregs,
    FPRegSet<X86_64>* fpregs);
template absl::Status ConvertRegsFromSnapshot(
    const Snapshot::RegisterState& register_state, GRegSet<AArch64>* gregs,
    FPRegSet<AArch64>* fpregs);

BorrowedMappingBytesList SplitBytesByMapping(
    const Snapshot::MemoryMappingList& memory_mapping_list,
    const Snapshot::MemoryBytesList& memory_byte_list) {
  // Create a list for each mapping.
  BorrowedMappingBytesList output{memory_mapping_list.size(),
                                  BorrowedMemoryBytesList()};

  // Assign each set of bytes to the corresponding mapping.
  // Note: this is O(n*m) but the number of mappings should stay relatively
  // low so doing something more optimal is not worth it at this point. Note:
  // the memory bytes are the outer loop so we can make sure none of the
  // memory bytes are lost.
  for (const auto& bytes : memory_byte_list) {
    bool found_mapping = false;
    for (size_t i = 0; i < memory_mapping_list.size(); ++i) {
      const Snapshot::MemoryMapping& mapping = memory_mapping_list[i];
      // Check if the bytes are completely inside the mapping.
      // Note: if, for some reason, the bytes are only partially inside a
      // mapping, this will result in !found_mapping.
      // Note: the following check is crafted to avoid overflow.
      if (mapping.start_address() <= bytes.start_address() &&
          bytes.start_address() - mapping.start_address() + bytes.num_bytes() <=
              mapping.num_bytes()) {
        // Borrow a reference from memory_byte_list.
        output[i].push_back(&bytes);
        found_mapping = true;
        break;
      }
    }
    if (!found_mapping) {
      // TODO(ncbray): propagate this error rather than LOG_FATAL.
      LOG_FATAL(
          "Bytes do not fit in a mapping: ", HexStr(bytes.start_address()),
          " + ", HexStr(bytes.num_bytes()));
    }
  }

  return output;
}

BorrowedMemoryBytesList ToBorrowedMemoryBytesList(
    const Snapshot::MemoryBytesList& memory_byte_list) {
  BorrowedMemoryBytesList output;
  output.reserve(memory_byte_list.size());
  for (const auto& bytes : memory_byte_list) {
    // Borrow a reference from memory_byte_list.
    output.push_back(&bytes);
  }
  return output;
}

absl::StatusOr<Snapshot::ByteData> GetInstructionBytesFromSnapshot(
    const Snapshot& snapshot) {
  // The initial RIP / PC should point to first instruction
  Snapshot::Address begin_code = snapshot.ExtractRip(snapshot.registers());

  // The end point should point to the beginning of the exit sequence.
  // This is also the end of the instructions that are unique to this Snapshot.
  // Trimming the exit sequence means that we should be able to re-make these
  // instructions and get the same snapshot.
  const Snapshot::EndStateList& end_states = snapshot.expected_end_states();
  if (end_states.empty()) {
    return absl::InternalError("Expected at least 1 end state");
  }
  Snapshot::Address end_code = end_states[0].endpoint().instruction_address();
  CHECK_LE(begin_code, end_code);
  for (const Snapshot::EndState& es : end_states) {
    Snapshot::Address other_end_code = es.endpoint().instruction_address();
    if (end_code != other_end_code) {
      return absl::InternalError(
          absl::StrCat("Endpoint position is inconsistent between endstates: ",
                       HexStr(end_code), " vs. ", HexStr(other_end_code)));
    }
  }

  // Normalizing the memory bytes should ensure all the instructions are inside
  // a single MemoryBytes object.
  Snapshot::MemoryBytesList mb = snapshot.memory_bytes();
  Snapshot::NormalizeMemoryBytes(snapshot.mapped_memory_map(), &mb);

  // Search for the instructions.
  for (const Snapshot::MemoryBytes& bytes : mb) {
    if (begin_code >= bytes.start_address() &&
        end_code <= bytes.limit_address()) {
      return bytes.byte_values().substr(begin_code - bytes.start_address(),
                                        end_code - begin_code);
    }
  }

  return absl::InternalError("Could not find instructions in the memory bytes");
}

}  // namespace silifuzz
