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

// Creates a Snapshot::ByteData from a Snap::MemoryBytes `memory_bytes`.
Snapshot::ByteData SnapMemoryBytesData(const Snap::MemoryBytes& memory_bytes) {
  if (memory_bytes.repeating) {
    return Snapshot::ByteData(memory_bytes.size(),
                              memory_bytes.data.byte_run.value);
  } else {
    return Snapshot::ByteData(
        reinterpret_cast<const char*>(memory_bytes.data.byte_values.elements),
        memory_bytes.size());
  }
}

}  // namespace

Snapshot::MemoryMappingList SnapMemoryMappings(const Snap& snap) {
  Snapshot::MemoryMappingList memory_mappings;
  for (const Snap::MemoryMapping& mapping : snap.memory_mappings) {
    const MemoryPerms perms = MemoryPerms::FromMProtect(mapping.perms);
    memory_mappings.push_back(Snapshot::MemoryMapping::MakeSized(
        mapping.start_address, mapping.num_bytes, perms));
  }
  return memory_mappings;
}

absl::StatusOr<Snapshot> SnapToSnapshot(const Snap& snap, PlatformId platform) {
  // TODO(ksteuck): [impl] x86 is hardcoded. We need to use "current"
  // architecture instead and also ensure it matches the target arch.
  Snapshot snapshot(Snapshot::Architecture::kX86_64, snap.id);
  for (const Snap::MemoryMapping& m : snap.memory_mappings) {
    RETURN_IF_NOT_OK(MemoryMapping::CanMakeSized(m.start_address, m.num_bytes));
    MemoryMapping mapping = MemoryMapping::MakeSized(
        m.start_address, m.num_bytes, MemoryPerms::FromMProtect(m.perms));
    RETURN_IF_NOT_OK(snapshot.can_add_memory_mapping(mapping));
    snapshot.add_memory_mapping(mapping);
  }
  for (const Snap::MemoryBytes& snap_mb : snap.memory_bytes) {
    Snapshot::ByteData data = SnapMemoryBytesData(snap_mb);
    Snapshot::MemoryBytes mb = {snap_mb.start_address, data};
    RETURN_IF_NOT_OK(snapshot.can_add_memory_bytes(mb));
    snapshot.add_memory_bytes(mb);
  }
  Snapshot::RegisterState rs =
      ConvertRegsToSnapshot(snap.registers.gregs, snap.registers.fpregs);
  snapshot.set_registers(rs);

  Snapshot::EndState es(Snapshot::Endpoint(snap.end_state_instruction_address),
                        ConvertRegsToSnapshot(snap.end_state_registers.gregs,
                                              snap.end_state_registers.fpregs));
  for (const Snap::MemoryBytes& snap_mb : snap.end_state_memory_bytes) {
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

}  // namespace silifuzz
