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

#include "./snap/testing/snap_generator_test_lib.h"

#include <cstddef>
#include <cstdint>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./common/mapped_memory_map.h"
#include "./common/memory_perms.h"
#include "./common/snapshot.h"
#include "./snap/gen/snap_generator.h"
#include "./snap/snap.h"
#include "./util/checks.h"
#include "./util/mem_util.h"
#include "./util/ucontext/serialize.h"

namespace silifuzz {
namespace {

// Verify functions: These checks that a Snap or its component is generated
// correctly from its source. If errors are found, they die.

// Verifies a field called 'name', which can be compared using == operator.
template <typename T1, typename T2>
void VerifySnapField(absl::string_view name, const T1& expect, const T2& got) {
  CHECK_EQ(expect, got);
}

// Verifies Snapshot::MemoryMapping -> SnapMemoryMapping conversion.
void VerifySnapMemoryMapping(const Snapshot::MemoryMapping& mapping,
                             const SnapMemoryMapping& snap_mapping) {
  VerifySnapField("start_address", mapping.start_address(),
                  snap_mapping.start_address);
  VerifySnapField("num_bytes", mapping.num_bytes(), snap_mapping.num_bytes);
  CHECK(MemoryPerms::FromMProtect(snap_mapping.perms) == mapping.perms());
}

// Verifies Snapshot::ByteData -> SnapArray<uint8_t> conversion.
void VerifyByteData(absl::string_view name, const Snapshot::ByteData byte_data,
                    const SnapArray<uint8_t>& snap_byte_data) {
  VerifySnapField(absl::StrCat(name, " size"), byte_data.size(),
                  snap_byte_data.size);
  for (int i = 0; i < byte_data.size(); ++i) {
    CHECK_EQ(static_cast<uint8_t>(byte_data.data()[i]),
             snap_byte_data.elements[i]);
  }
}

// Verifies Snapshot::ByteData -> SnapArray<uint8_t> conversion.
void VerifyByteRun(absl::string_view name, const Snapshot::ByteData byte_data,
                   const SnapMemoryBytes::ByteRun snap_byte_run) {
  VerifySnapField(absl::StrCat(name, " size"), byte_data.size(),
                  snap_byte_run.size);
  CHECK(
      MemAllEqualTo(byte_data.data(), snap_byte_run.value, snap_byte_run.size));
}

// Verifies Snapshot::MemoryBytes -> SnapMemoryBytes conversion.
void VerifySnapMemoryBytes(const Snapshot::MemoryBytes& memory_bytes,
                           const SnapMemoryBytes& snap_memory_bytes,
                           const MappedMemoryMap& mapped_memory_map) {
  VerifySnapField("start_address", memory_bytes.start_address(),
                  snap_memory_bytes.start_address);
  const Snapshot::Address snap_memory_bytes_limit =
      snap_memory_bytes.start_address + snap_memory_bytes.size();
  CHECK(mapped_memory_map.Contains(snap_memory_bytes.start_address,
                                   snap_memory_bytes_limit));
  MemoryPerms perms =
      mapped_memory_map.Perms(snap_memory_bytes.start_address,
                              snap_memory_bytes_limit, MemoryPerms::kOr);
  CHECK(perms == mapped_memory_map.Perms(snap_memory_bytes.start_address,
                                         snap_memory_bytes_limit,
                                         MemoryPerms::kAnd));
  if (snap_memory_bytes.repeating()) {
    VerifyByteRun("byte_run", memory_bytes.byte_values(),
                  snap_memory_bytes.data.byte_run);
  } else {
    VerifyByteData("byte_values", memory_bytes.byte_values(),
                   snap_memory_bytes.data.byte_values);
  }
}

// Verifies Snapshot::RegisterState -> Snap::RegisterState conversion.
template <typename Arch>
void VerifySnapRegisterState(
    const Snapshot::RegisterState& registers,
    const typename Snap<Arch>::RegisterState& snap_registers) {
  Snapshot::ByteData gregs_bytes;
  CHECK(SerializeGRegs(snap_registers.gregs, &gregs_bytes));
  CHECK_EQ(registers.gregs(), gregs_bytes);

  Snapshot::ByteData fpregs_bytes;
  CHECK(SerializeFPRegs(snap_registers.fpregs, &fpregs_bytes));
  CHECK_EQ(registers.fpregs(), fpregs_bytes);
}

// Verifies Snapshot::MemoryBytesList -> SnapArray<SnapMemoryBytes>
// conversion.
void VerifySnapMemoryBytesArray(
    absl::string_view name, const BorrowedMemoryBytesList& memory_bytes_list,
    const SnapArray<SnapMemoryBytes>& snap_memory_bytes_list,
    const MappedMemoryMap& mapped_memory_map) {
  VerifySnapField(absl::StrCat(name, " size"), memory_bytes_list.size(),
                  snap_memory_bytes_list.size);
  size_t snap_array_index = 0;
  for (const auto& memory_bytes : memory_bytes_list) {
    VerifySnapMemoryBytes(*memory_bytes,
                          snap_memory_bytes_list.elements[snap_array_index],
                          mapped_memory_map);
    snap_array_index++;
  }
}

// Verifies Snapshot::MemoryMappingList -> SnapArray<SnapMemoryMappging>
// conversion.
void VerifySnapMemoryMappingArray(
    absl::string_view name, const Snapshot::MemoryMappingList& memory_mappings,
    const SnapArray<SnapMemoryMapping>& snap_memory_mappings) {
  VerifySnapField(absl::StrCat(name, " size"), memory_mappings.size(),
                  snap_memory_mappings.size);
  size_t snap_array_index = 0;
  for (const auto& memory_mapping : memory_mappings) {
    VerifySnapMemoryMapping(memory_mapping,
                            snap_memory_mappings.elements[snap_array_index]);
    snap_array_index++;
  }
}

}  // namespace

// Verifies that 'snapshot' is correctly converted into 'snap'.
template <typename Arch>
void VerifyTestSnap(const Snapshot& snapshot, const Snap<Arch>& snap,
                    const SnapifyOptions& generator_options) {
  absl::StatusOr<Snapshot> snapified_snapshot_or =
      Snapify(snapshot, generator_options);
  CHECK_STATUS(snapified_snapshot_or.status());
  const Snapshot& snapified_snapshot = snapified_snapshot_or.value();

  VerifySnapField("id", snapified_snapshot.id(), snap.id);
  VerifySnapMemoryMappingArray("memory_mappings",
                               snapified_snapshot.memory_mappings(),
                               snap.memory_mappings);

  BorrowedMappingBytesList bytes_per_mapping = SplitBytesByMapping(
      snapified_snapshot.memory_mappings(), snapified_snapshot.memory_bytes());

  for (size_t i = 0; i < snap.memory_mappings.size; ++i) {
    VerifySnapMemoryBytesArray("memory_bytes", bytes_per_mapping[i],
                               snap.memory_mappings[i].memory_bytes,
                               snapified_snapshot.mapped_memory_map());
  }
  VerifySnapRegisterState<Arch>(snapified_snapshot.registers(),
                                *snap.registers);
  CHECK_EQ(snapified_snapshot.expected_end_states().size(), 1);
  const Snapshot::EndState& end_state =
      snapified_snapshot.expected_end_states()[0];
  const Snapshot::Endpoint& endpoint = end_state.endpoint();
  CHECK(endpoint.type() == Snapshot::Endpoint::kInstruction);
  VerifySnapField("end_state_instruction_address",
                  endpoint.instruction_address(),
                  snap.end_state_instruction_address);
  VerifySnapRegisterState<Arch>(end_state.registers(),
                                *snap.end_state_registers);

  VerifySnapMemoryBytesArray(
      "memory_bytes", ToBorrowedMemoryBytesList(end_state.memory_bytes()),
      snap.end_state_memory_bytes, snapified_snapshot.mapped_memory_map());
}

template void VerifyTestSnap(const Snapshot& snapshot, const Snap<X86_64>& snap,
                             const SnapifyOptions& generator_options);
template void VerifyTestSnap(const Snapshot& snapshot,
                             const Snap<AArch64>& snap,
                             const SnapifyOptions& generator_options);

}  // namespace silifuzz
