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

#ifndef THIRD_PARTY_SILIFUZZ_PROXIES_PAGE_TABLE_PAGE_TABLE_CREATOR_H_
#define THIRD_PARTY_SILIFUZZ_PROXIES_PAGE_TABLE_PAGE_TABLE_CREATOR_H_

#include <stddef.h>
#include <stdint.h>

#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "./common/memory_mapping.h"
#include "./proxies/page_table/physical_address.h"
#include "./util/arch.h"

namespace silifuzz::proxies {

// Represents a four-level page table supporting 48-bit addresses with
// translation granule size of 4KiB. Should only be used for stage 1 address
// translation (i.e. no intermediate physical addresses).
//
// Example:
//
// Let's say we want to include a page table in an ELF's .rodata at
// <page_table_pa>.
//
// We want the page table to map code pages [code_va, code_va + code_size) ->
// [code_pa, code_pa + code_size) and data pages [data_va, data_va + data_size)
// -> [data_pa, data_pa + data_size).
//
// We'd have the following pseudo-code.
//
// PageTableCreator creator(<page_table_pa>);
// CHECK_OK(creator.AddContiguousMapping(
//     MemoryMapping::MakeSized(<code_va>, <code_size>, MemoryPerms::XR()),
//     <code_pa>));
// CHECK_OK(creator.AddContiguousMapping(
//     MemoryMapping::MakeSized(<data_va>, <data_size>, MemoryPerms::RW()),
//     <data_pa>));
// const std::vector<uint64_t> &data = creator.GetBinaryData();
// <copy data to <page_table_pa> in ELF file>
template <typename arch>
class PageTableCreator {
 public:
  // Create a page table where the L0 page should be placed at
  // `page_table_addr` in physical address space. `page_table_addr` must be
  // aligned to the translation granule (4KiB).
  explicit PageTableCreator(uint64_t page_table_addr);

  // Set up page table so that the provided `mapping` translates to
  // `physical_addr`. The physical address and mapping's starting address/size
  // should be aligned to the translation granule (4KiB).
  //
  // The permission bits of `mapping` specify whether the page table should
  // accept write and unprivileged execute accesses. Returns error if this
  // conflicts with an existing mapping.
  absl::Status AddContiguousMapping(MemoryMapping mapping,
                                    uint64_t physical_addr);

  // Returns the binary data for the page table that can be copied to
  // `page_table_addr_`. This representation only contains pages needed for the
  // mappings added.
  const std::vector<uint64_t> &GetBinaryData() { return entries_; }

  // Virtual addresses are mapped to physical address at a 4KiB granularity.
  // Equivalent to page size.
  static constexpr uint64_t kTranslationGranule = 0x1000;

 private:
  // Constant for the four-level page table.
  static constexpr size_t kNumLevels = 4;

  // Decode the virtual address for easy access to the page tables.
  struct DecodedVirtualAddress {
    // Value of the virtual address.
    uint64_t value;
    // For each level of the page table, indicates the starting virtual address
    // for the interval that would correspond to the correct page.
    uint64_t starting_interval[kNumLevels];
    // For each level of the page table, indicates the index of the specific
    // entry in the correct page.
    uint64_t entry_index[kNumLevels];

    explicit DecodedVirtualAddress(uint64_t virtual_addr);
  };

  // Checks that the value is 4KiB-aligned and fits within a 48-bit address
  // space. `descriptor` describes the value in case of error.
  static absl::Status CheckAlignmentAndSize(uint64_t value,
                                            absl::string_view descriptor);

  // Finds the page table entry corresponding to a `decoded_va` at the
  // specified `level`. If the requested page table entry does not already
  // exist, add the new page of entries to `entries_` and populate
  // `page_tables_[level]`.
  //
  // Returns the index of the found page table entry in entries_.
  size_t GetPageTableEntryIndex(DecodedVirtualAddress decoded_va, size_t level);

  // Given 4KiB-aligned `decoded_va` and `decoded_pa`, setup the L3 page
  // descriptor entry with `writeable` and `executable` attributes.
  //
  // Returns error if the L3 page table entry corresponding to the virtual
  // address already contains a mapping to a different physical address or
  // with different writeable/executable permissions.
  absl::Status SetupPageDescriptor(DecodedVirtualAddress decoded_va,
                                   PhysicalAddress decoded_pa, bool writeable,
                                   bool executable);

  // Given a 4KiB-aligned `decoded_va`, setup the specified `level` table
  // descriptor entry with pointers to the correct next table address.
  //
  // If the table descriptor entry already exists (for a different mapping),
  // update the `writeable` and `executable` attributes of a page to be the most
  // permissive required for the mappings behind it.
  // (Note: The L3 page table entry will enforce the correct permissions per
  // physical page. The permissions at this stage simply allow short-circuiting
  // of page faults.)
  //
  // This function will recursively call `SetupTableDescriptor` for the lower
  // level (if there is a lower level).
  void SetupTableDescriptor(size_t level, DecodedVirtualAddress decoded_va,
                            bool writeable, bool executable);

  // Flattened vector holding the entries for every page of the page table that
  // has been touched by a mapping. The ordering of entries corresponds to the
  // final ordering in physical address space (starting with the L0 page),
  // meaning this vector can be directly copied to the `page_table_addr_`
  // in memory.
  //
  // Every 512 64-bit entries comprise a 4KiB page. L0-2 entries are next-level
  // table descriptors while L3 entries are physical page descriptors.
  std::vector<uint64_t> entries_;

  // These sparsely populated hash maps represent the levels of the page table.
  // Key: Starting address of virtual address interval represented by 4KiB page.
  // Value: Index into entries_ for that page.
  //
  // Page Level | Virtual Address Interval Size | Entry Type
  // ---------- | ----------------------------- | ---------------------------
  // L0         | (1 << 48) bytes               | next-level table descriptor
  // L1         | (1 << 39) bytes               | next-level table descriptor
  // L2         | (1 << 30) bytes               | next-level table descriptor
  // L3         | (1 << 21) bytes               | physical page descriptor
  absl::flat_hash_map<uint64_t, uint64_t> page_tables_[kNumLevels];

  // Physical address that the L0 page table is intended to start at.
  uint64_t page_table_addr_;
};

}  // namespace silifuzz::proxies

#endif  // THIRD_PARTY_SILIFUZZ_PROXIES_PAGE_TABLE_PAGE_TABLE_CREATOR_H_
