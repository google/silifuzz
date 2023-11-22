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

#ifndef THIRD_PARTY_SILIFUZZ_PROXIES_PAGE_TABLE_PHYSICAL_ADDRESS_H_
#define THIRD_PARTY_SILIFUZZ_PROXIES_PAGE_TABLE_PHYSICAL_ADDRESS_H_

#include <cstdint>

#include "./proxies/page_table/bit_struct.h"

namespace silifuzz::proxies::dsim {

// Represents how a 48-bit physical address is composed of bits taken directly
// from and translated from the virtual address (for a 4KB translation granule).
// Reference: ARM Architecture Reference Manual, Figure D8-3
class PhysicalAddress : public BitStruct {
 public:
  constexpr PhysicalAddress() = default;
  explicit constexpr PhysicalAddress(uint64_t bits) : BitStruct(bits) {}
  ~PhysicalAddress() = default;

  // Copyable and movable by default.
  PhysicalAddress(const PhysicalAddress&) = default;
  PhysicalAddress& operator=(const PhysicalAddress&) = default;
  PhysicalAddress(PhysicalAddress&&) = default;
  PhysicalAddress& operator=(PhysicalAddress&&) = default;

  // Bit fields in PhysicalAddress:
  //
  // These bits determine the offset within a 4KB translation granule. These
  // bits are taken directly without translation from the corresponding least
  // significant bits of the input virtual address.
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(physical_address_lsbs, 0, 11)

  // These bits represent the 4KB page for this address in physical memory.
  // These bits are taken from the L3 page table's page descriptor entry after
  // walking four levels of address translation.
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(physical_address_msbs, 12, 47)
};

}  // namespace silifuzz::proxies::dsim

#endif  // THIRD_PARTY_SILIFUZZ_PROXIES_PAGE_TABLE_PHYSICAL_ADDRESS_H_
