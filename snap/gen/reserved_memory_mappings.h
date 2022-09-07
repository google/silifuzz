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

#ifndef THIRD_PARTY_SILIFUZZ_SNAP_GEN_RESERVED_MEMORY_MAPPINGS_H_
#define THIRD_PARTY_SILIFUZZ_SNAP_GEN_RESERVED_MEMORY_MAPPINGS_H_

#include "./common/mapped_memory_map.h"
#include "./common/snapshot.h"

// Memory mappings for regions not usable by any Snaps.
// This information is used by different tools like generator and maker.

namespace silifuzz {

// Returns a MappedMemoryMap for all memory ranges that a Snap should not
// include, with the exception of the very last byte at 0xffffffffffffffff due
// to limitation of MappedMemoryMap. Callers should only check for address
// containment using the returned map. Memory permissions in the returned
// map are all of the same value MemoryPerm::All().
const MappedMemoryMap& ReservedMemoryMappings();

// Returns true iff any of `memory_mappings` overlaps with reserved memory
// mappings.
bool OverlapReservedMemoryMappings(
    const Snapshot::MemoryMappingList& memory_mappings);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_SNAP_GEN_RESERVED_MEMORY_MAPPINGS_H_
