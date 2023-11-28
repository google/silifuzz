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

#ifndef THIRD_PARTY_SILIFUZZ_PROXIES_PAGE_TABLE_X86_64_TABLE_DESCRIPTOR_ENTRY_H_
#define THIRD_PARTY_SILIFUZZ_PROXIES_PAGE_TABLE_X86_64_TABLE_DESCRIPTOR_ENTRY_H_

#include <cstdint>

#include "./proxies/page_table/bit_struct.h"
#include "./util/arch.h"

namespace silifuzz::proxies {

// Represents a page table entry intended to describe another page table
// for 'arch'.
template <typename arch>
class TableDescriptorEntry;

// Represents a page table entry intended to describe another page table on
// x86-64.
//
// This entry is a translation setup with 4KB translation granules and 48-bit
// physical addresses. Although the hardware supports also 2MB and 1GB page
// sizes, those are not supported here.
//
// Reference: Intel 64 and IA-32 Architectures Software Developer’s Manual,
// Volume 3: System Programming Guide.
template <>
class TableDescriptorEntry<X86_64> : public BitStruct {
 public:
  // Value encodings for fields.
  enum read_write_value { kReadOnly = 0, kReadWrite = 1 };

  enum user_supervisor_value {
    kSupervisorModeOnly = 0,
    kUserModeAccessAllowed = 1
  };

  explicit constexpr TableDescriptorEntry(uint64_t bits) : BitStruct(bits) {}
  ~TableDescriptorEntry() = default;

  // Copyable and movable by default.
  TableDescriptorEntry(const TableDescriptorEntry&) = default;
  TableDescriptorEntry& operator=(const TableDescriptorEntry&) = default;
  TableDescriptorEntry(TableDescriptorEntry&&) = default;
  TableDescriptorEntry& operator=(TableDescriptorEntry&&) = default;

  // Bit fields in TableDescriptorEntry:
  // Reference: Intel 64 and IA-32 Architectures SDM Vol. 3A, Table 4-14.
  // Note, this applies to all levels of table descriptors (PML4E, PDPTE,
  // and Page-Directory).
  //
  // Present; must be 1 to map a 4-kByte page.
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(present, 0, 0)

  // Read/write; if 0, writes may not be allowed to the region controlled by
  // this entry.
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(read_write, 1, 1)

  // User/supervisor; if 0, user-mode accesses are not allowed to the region
  // controlled by this entry.
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(user_supervisor, 2, 2)

  // Page-level write-through; indirectly determines the memory type used to
  // access the next level descriptors referenced by this entry.
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(page_write_through, 3, 3)

  // Page-level cache disable; indirectly determines the memory type used to
  // access the next level descriptors referenced by this entry.
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(page_cache_disable, 4, 4)

  // Accessed; indicates whether this entry has been used for linear-address
  // translation.
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(accessed, 5, 5)

  // Ignored.
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(ignored0, 6, 6)

  // Reserved/Not used for 4-kByte page size translation (must be 0).
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(page_size, 7, 7)

  // Ignored.
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(ignored1, 8, 11)

  // Physical address of 4-KByte aligned next level table/page table referenced
  // by this entry.
  // Bits [MAXPHYADDR:51] must be zero. See section 4.1.4 of SDM vol. 3A.
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(physical_address, 12, 51)

  // Ignored.
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(ignored2, 52, 62)

  // If IA32_EFER.NXE = 1, execute-disable (if 1, instruction fetches are not
  // allowed from the region controlled by this entry; see Section 4.6);
  // otherwise, reserved (must be 0).
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(execute_disable, 63, 63)

  // Default constructor has to be defined after field declarations.
  constexpr TableDescriptorEntry() : BitStruct() {
    set_present(1)
        .set_read_write(kReadOnly)
        .set_user_supervisor(kUserModeAccessAllowed)
        .set_page_write_through(0)
        .set_page_cache_disable(0)
        .set_accessed(0)
        .set_page_size(0)
        .set_execute_disable(1);
  }
};

}  // namespace silifuzz::proxies

#endif  // THIRD_PARTY_SILIFUZZ_PROXIES_PAGE_TABLE_X86_64_TABLE_DESCRIPTOR_ENTRY_H_
