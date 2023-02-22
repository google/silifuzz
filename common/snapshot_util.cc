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

#include "absl/status/statusor.h"
#include "./common/snapshot_proto.h"
#include "./util/checks.h"
#include "./util/proto_util.h"
#include "./util/ucontext/serialize.h"

namespace silifuzz {

absl::Status WriteSnapshotToFile(const Snapshot& snapshot,
                                 absl::string_view filename) {
  proto::Snapshot proto;
  SnapshotProto::ToProto(snapshot, &proto);
  return WriteToFile(proto, filename);
}

void WriteSnapshotToFileOrDie(const Snapshot& snapshot,
                              absl::string_view filename) {
  auto s = WriteSnapshotToFile(snapshot, filename);
  CHECK_STATUS(s);
}

absl::StatusOr<Snapshot> ReadSnapshotFromFile(absl::string_view filename) {
  proto::Snapshot snap_proto;
  auto s = ReadFromFile(filename, &snap_proto);
  RETURN_IF_NOT_OK(s);

  auto snapshot_or = SnapshotProto::FromProto(snap_proto);
  RETURN_IF_NOT_OK_PLUS(snapshot_or.status(),
                        "Could not parse Snapshot from proto: ");
  return snapshot_or;
}

Snapshot ReadSnapshotFromFileOrDie(absl::string_view filename) {
  auto snapshot_or = ReadSnapshotFromFile(filename);
  CHECK_STATUS(snapshot_or.status());
  return std::move(snapshot_or).value();
}

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

}  // namespace silifuzz
