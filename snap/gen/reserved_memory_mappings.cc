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

#include "./snap/gen/reserved_memory_mappings.h"

#include "./common/mapped_memory_map.h"
#include "./common/memory_perms.h"
#include "./common/snapshot.h"
#include "./snap/exit_sequence.h"
#include "./snap/gen/runner_base_address.h"

namespace silifuzz {

const MappedMemoryMap& ReservedMemoryMappings() {
  static const MappedMemoryMap instance = ([]() -> MappedMemoryMap {
    MappedMemoryMap mapped_memory_map;
    const MemoryPerms perms = MemoryPerms::All();
    // First 64k in user address space. The OS normally keeps this region
    // unmapped to detect NULL pointer dereference.
    mapped_memory_map.Add(0x0, 0x10000, perms);

    // Exit sequence.
    mapped_memory_map.Add(kSnapExitAddress, kSnapExitAddress + (1 << 12),
                          perms);

    // Runner binary region. We reserve for the runner.
    mapped_memory_map.Add(SILIFUZZ_RUNNER_BASE_ADDRESS,
                          SILIFUZZ_RUNNER_BASE_ADDRESS + (1ULL << 32), perms);

#if defined(__x86_64__)
    // Stack and VDSO near end of user space.
    mapped_memory_map.Add(0x7f0000000000ULL, 0x800000000000ULL, perms);

    // From end of user space to end of address space minus the last byte,
    // which cannot be specified in and address range.
    mapped_memory_map.Add(0x800000000000ULL, 0xffffffffffffffffULL, perms);
#elif defined(__aarch64__)
    // Stack and VDSO near end of user space.
    // 19 bits of entropy and 12 bits of page size.
    mapped_memory_map.Add(0x0000ffff80000000ULL, 0x0001000000000000ULL, perms);

    // User addresses have bits 63:48 set to 0.
    // See: https://docs.kernel.org/arm64/memory.html
    mapped_memory_map.Add(0x0001000000000000ULL, 0xffffffffffffffffULL, perms);
#else
#error "need to define architecture specific reserved memory mappings".
#endif

    return mapped_memory_map;
  })();

  return instance;
}

bool OverlapReservedMemoryMappings(
    const Snapshot::MemoryMappingList& memory_mappings) {
  const MappedMemoryMap& reserved_memory_mappings = ReservedMemoryMappings();
  for (const auto& mapping : memory_mappings) {
    if (reserved_memory_mappings.Overlaps(mapping.start_address(),
                                          mapping.limit_address()))
      return true;
  }
  return false;
}

}  // namespace silifuzz
