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

#ifndef THIRD_PARTY_SILIFUZZ_PROXIES_PAGE_TABLE_AARCH64_TABLE_DESCRIPTOR_ENTRY_H_
#define THIRD_PARTY_SILIFUZZ_PROXIES_PAGE_TABLE_AARCH64_TABLE_DESCRIPTOR_ENTRY_H_

#include <cstdint>

#include "./proxies/page_table/bit_struct.h"
#include "./util/arch.h"

namespace silifuzz::proxies::dsim {

// Represents a page table entry intended to describe another page table
// for 'arch'.
template <typename arch>
class TableDescriptorEntry;

// Represents a page table entry intended to describe another page table on
// AArch64.
//
// This entry is a translation setup with 4KB translation granules and 48-bit
// physical addresses for a stage 1 translation.
// Reference: ARM Architecture Reference Manual, Figure D8-12
//
// Note: One-stage translation indicates that the input virtual address is being
// translated to a physical output address. Two-stage translation indicates that
// the input virtual address is being translated to an IPA (intermediate
// physical address), which is then translated to the physical address.
// Reference: ARM Architecture Reference Manual, Page D8-5080
template <>
class TableDescriptorEntry<AArch64> : public BitStruct {
 public:
  // Value encodings for fields.
  enum ap_table_unprivileged_access_value {
    kApTableUnprivilegedAccessPermitted = 0,
    kApTableUnprivilegedAccessNotPermitted = 1
  };

  enum ap_table_write_access_value {
    kApTableWriteAccessReadWrite = 0,
    kApTableWriteAccessReadOnly = 1
  };

  enum ns_table_value {
    kNsTableSecurePaSpace = 0,
    kNsTableNonSecurePaSpace = 1
  };

  enum pxn_table_value {
    kPxnTableNoEffect = 0,
    kPxnTablePrivilegedExecuteNever = 1
  };

  enum type_value { kTypeBlock = 0, kTypeTable = 1 };

  enum uxn_table_value {
    kUxnTableNoEffect = 0,
    kUxnTableUnprivilegedExecuteNever = 1
  };

  explicit constexpr TableDescriptorEntry(uint64_t bits) : BitStruct(bits) {}
  ~TableDescriptorEntry() = default;

  // Copyable and movable by default.
  TableDescriptorEntry(const TableDescriptorEntry&) = default;
  TableDescriptorEntry& operator=(const TableDescriptorEntry&) = default;
  TableDescriptorEntry(TableDescriptorEntry&&) = default;
  TableDescriptorEntry& operator=(TableDescriptorEntry&&) = default;

  // Bit fields in TableDescriptorEntry:
  //
  // Indicates whether the page table entry is valid.
  // Reference: ARM Cortex-A Series Programmer's Guide for ARMv8-A, Fig 12-10
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(valid, 0, 0)

  // Indicates whether the page table entry is a table or block entry.
  // Note: We initialize this to 0x1 (table) for this bit struct description.
  // Reference: ARM Cortex-A Series Programmer's Guide for ARMv8-A, Fig 12-10
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(type, 1, 1)

  // Ignored
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(ignored0, 2, 11)

  // Address of the next-level page table.
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(next_table_address, 12, 47)

  // Reserved
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(res0, 48, 50)

  // Ignored
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(ignored1, 51, 58)

  // Only meaningful for stage 1 translations in secure state.
  // For stage 1 translations that support two privilege levels, determines
  // the privileged execute-never limit for subsequent lookup levels.
  // Reference: ARM Architecture Reference Manual, Page D8-5142
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(pxn_table, 59, 59)

  // Only meaningful for stage 1 translations in secure state.
  // For stage 1 translations that support two privilege levels, determines
  // the unprivileged execute-never limit for subsequent lookup levels at EL0.
  // Reference: ARM Architecture Reference Manual, Page D8-5142
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(uxn_table, 60, 60)

  // Translation table entries at a given lookup level can limit data access
  // permissions at subsequent lookup levels.
  // Reference: ARM Architecture Reference Manual, Table D8-41, Section D8.4.3
  // Note: This enum is backwards of the same enum in page descriptor entries.
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(ap_table_unprivileged_access, 61, 61)

  // Translation table entries at a given lookup level can limit data access
  // permissions at subsequent lookup levels.
  // Reference: ARM Architecture Reference Manual, Table D8-41, Section D8.4.3
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(ap_table_write_access, 62, 62)

  // Only meaningful for stage 1 translations in secure state. Indicates
  // whether an access to the output address specified by the descriptor is to
  // non-secure or secure physical address space.
  // Reference: ARM Architecture Reference Manual, Section D8.4.2
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(ns_table, 63, 63)

  // Default constructor has to be defined after field declarations.
  constexpr TableDescriptorEntry() : BitStruct() {
    set_type(kTypeTable)
        .set_pxn_table(kPxnTableNoEffect)
        .set_uxn_table(kUxnTableUnprivilegedExecuteNever)
        .set_ap_table_unprivileged_access(kApTableUnprivilegedAccessPermitted)
        .set_ap_table_write_access(kApTableWriteAccessReadOnly)
        .set_ns_table(kNsTableNonSecurePaSpace);
  }
};

}  // namespace silifuzz::proxies::dsim

#endif  // THIRD_PARTY_SILIFUZZ_PROXIES_PAGE_TABLE_AARCH64_TABLE_DESCRIPTOR_ENTRY_H_
