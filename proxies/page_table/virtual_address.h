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

#ifndef THIRD_PARTY_SILIFUZZ_PROXIES_PAGE_TABLE_VIRTUAL_ADDRESS_H_
#define THIRD_PARTY_SILIFUZZ_PROXIES_PAGE_TABLE_VIRTUAL_ADDRESS_H_

#include <cstdint>

#include "absl/log/log.h"
#include "./proxies/page_table/bit_struct.h"

namespace silifuzz::proxies::dsim {

// Represents how a 48-bit virtual address resolves into translation table
// indices and the least significant bits of the physical address for a 4KB
// translation granule.
// Reference: ARM Architecture Reference Manual, Figure D8-3
// Reference: ARM Cortex-A Series Programmer's Guide for ARMv8-A, Figure 12-11
class VirtualAddress : public BitStruct {
 public:
  constexpr VirtualAddress() = default;
  explicit constexpr VirtualAddress(uint64_t bits) : BitStruct(bits) {}
  ~VirtualAddress() = default;

  // Copyable and movable by default.
  VirtualAddress(const VirtualAddress&) = default;
  VirtualAddress& operator=(const VirtualAddress&) = default;
  VirtualAddress(VirtualAddress&&) = default;
  VirtualAddress& operator=(VirtualAddress&&) = default;

  // Bit fields in VirtualAddress:
  //
  // The least significant bits of the input virtual address determine the
  // offset within the 4KB translation.
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(physical_address_lsbs, 0, 11)

  // Index of the corresponding entry in the L3 translation table.
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(table_index_l3, 12, 20)

  // Index of the corresponding entry in the L3 translation table.
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(table_index_l2, 21, 29)

  // Index of the corresponding entry in the L3 translation table.
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(table_index_l1, 30, 38)

  // Index of the corresponding entry in the L3 translation table.
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(table_index_l0, 39, 47)

  // Convenience methods for accessing table indices l0-l3 as an array.
  inline uint64_t table_index_l(int index) const {
    switch (index) {
      case 0:
        return table_index_l0();
      case 1:
        return table_index_l1();
      case 2:
        return table_index_l2();
      case 3:
        return table_index_l3();
      default:
        LOG(FATAL) << "table_index_l index is invalid. ";
    }
  }

  inline VirtualAddress& set_table_index_l(int index, uint64_t value) {
    switch (index) {
      case 0:
        return set_table_index_l0(value);
      case 1:
        return set_table_index_l1(value);
      case 2:
        return set_table_index_l2(value);
      case 3:
        return set_table_index_l3(value);
      default:
        LOG(FATAL) << "table_index_l index is invalid. ";
    }
  }
};

}  // namespace silifuzz::proxies::dsim

#endif  // THIRD_PARTY_SILIFUZZ_PROXIES_PAGE_TABLE_VIRTUAL_ADDRESS_H_
