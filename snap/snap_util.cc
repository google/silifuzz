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

#include "./snap/snap_util.h"

#include "absl/status/statusor.h"
#include "./common/memory_mapping.h"
#include "./common/memory_perms.h"
#include "./common/snapshot.h"
#include "./common/snapshot_util.h"
#include "./snap/snap.h"
#include "./util/checks.h"
#include "./util/platform.h"

namespace silifuzz {

namespace {

// Creates a Snapshot::ByteData from a SnapMemoryBytes `memory_bytes`.
Snapshot::ByteData SnapMemoryBytesData(const SnapMemoryBytes& memory_bytes) {
  if (memory_bytes.repeating()) {
    return Snapshot::ByteData(memory_bytes.size(),
                              memory_bytes.data.byte_run.value);
  } else {
    return Snapshot::ByteData(
        reinterpret_cast<const char*>(memory_bytes.data.byte_values.elements),
        memory_bytes.size());
  }
}

}  // namespace

template <typename Arch>
absl::StatusOr<Snapshot> SnapToSnapshot(const Snap<Arch>& snap,
                                        PlatformId platform) {
  CHECK(Arch::architecture_id == PlatformArchitecture(platform));
  Snapshot snapshot(Snapshot::ArchitectureTypeToEnum<Arch>(), snap.id);
  for (const SnapMemoryMapping& m : snap.memory_mappings) {
    RETURN_IF_NOT_OK(MemoryMapping::CanMakeSized(m.start_address, m.num_bytes));
    MemoryMapping mapping = MemoryMapping::MakeSized(
        m.start_address, m.num_bytes, MemoryPerms::FromMProtect(m.perms));
    RETURN_IF_NOT_OK(snapshot.can_add_memory_mapping(mapping));
    snapshot.add_memory_mapping(mapping);
    for (const SnapMemoryBytes& snap_mb : m.memory_bytes) {
      Snapshot::ByteData data = SnapMemoryBytesData(snap_mb);
      Snapshot::MemoryBytes mb = {snap_mb.start_address, data};
      RETURN_IF_NOT_OK(snapshot.can_add_memory_bytes(mb));
      snapshot.add_memory_bytes(mb);
    }
  }
  Snapshot::RegisterState rs =
      ConvertRegsToSnapshot(*snap.registers.gregs, *snap.registers.fpregs);
  snapshot.set_registers(rs);

  Snapshot::EndState es(
      Snapshot::Endpoint(snap.end_state_instruction_address),
      ConvertRegsToSnapshot(*snap.end_state_registers.gregs,
                            *snap.end_state_registers.fpregs));
  for (const SnapMemoryBytes& snap_mb : snap.end_state_memory_bytes) {
    Snapshot::ByteData data = SnapMemoryBytesData(snap_mb);
    Snapshot::MemoryBytes mb = {snap_mb.start_address, data};
    RETURN_IF_NOT_OK(es.can_add_memory_bytes(mb));
    es.add_memory_bytes(mb);
  }

  es.add_platform(platform);

  RETURN_IF_NOT_OK(snapshot.can_add_expected_end_state(es));
  snapshot.add_expected_end_state(es);
  return snapshot;
}

template absl::StatusOr<Snapshot> SnapToSnapshot(const Snap<X86_64>& snap,
                                                 PlatformId platform);
template absl::StatusOr<Snapshot> SnapToSnapshot(const Snap<AArch64>& snap,
                                                 PlatformId platform);

}  // namespace silifuzz
