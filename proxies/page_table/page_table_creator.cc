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

#include "./proxies/page_table/page_table_creator.h"

#include <stddef.h>
#include <stdint.h>

#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "./common/memory_mapping.h"
#include "./common/memory_perms.h"
#include "./proxies/page_table/page_table_entry_util.h"
#include "./proxies/page_table/physical_address.h"
#include "./proxies/page_table/virtual_address.h"
#include "./util/arch.h"
#include "./util/checks.h"

namespace silifuzz::proxies {

namespace {

// Width of supported addresses for all architectures.
constexpr size_t kAddressWidthBits = 48;

}  // namespace

template <typename arch>
PageTableCreator<arch>::PageTableCreator(uint64_t page_table_addr)
    : entries_(), page_table_addr_(page_table_addr) {
  CHECK_OK(CheckAlignmentAndSize(page_table_addr_, "page_table_addr"));
  // Create L0 page in entries_ as it needs to be the first page in the bit
  // representation (in order for the page table to start at `page_table_addr`).
  uint64_t l0_starting_interval = 0;
  page_tables_[0][l0_starting_interval] = entries_.size();
  entries_.resize(kTranslationGranule / sizeof(uint64_t));
}

template <typename arch>
absl::Status PageTableCreator<arch>::AddContiguousMapping(
    MemoryMapping mapping, uint64_t physical_addr) {
  RETURN_IF_NOT_OK(
      CheckAlignmentAndSize(mapping.start_address(), "starting virtual_addr"));
  RETURN_IF_NOT_OK(
      CheckAlignmentAndSize(physical_addr, "starting physical_addr"));
  RETURN_IF_NOT_OK(CheckAlignmentAndSize(mapping.num_bytes(), "size"));
  RETURN_IF_NOT_OK(CheckAlignmentAndSize(
      mapping.start_address() + mapping.num_bytes() - kTranslationGranule,
      "ending virtual_addr"));
  RETURN_IF_NOT_OK(CheckAlignmentAndSize(
      physical_addr + mapping.num_bytes() - kTranslationGranule,
      "ending physical_addr"));

  bool writeable = mapping.perms().Has(MemoryPerms::kWritable);
  bool executable = mapping.perms().Has(MemoryPerms::kExecutable);

  for (size_t byte_offset = 0; byte_offset < mapping.num_bytes();
       byte_offset += kTranslationGranule) {
    PageTableCreator::DecodedVirtualAddress decoded_va(mapping.start_address() +
                                                       byte_offset);
    PhysicalAddress decoded_pa(physical_addr + byte_offset);
    RETURN_IF_NOT_OK(
        SetupPageDescriptor(decoded_va, decoded_pa, writeable, executable));
    // Note: We populate entries from L2 -> L0 because we need to populate
    // next-level table pointers.
    SetupTableDescriptor(/*level=*/2, decoded_va, writeable, executable);
  }
  return absl::OkStatus();
}

template <typename arch>
PageTableCreator<arch>::DecodedVirtualAddress::DecodedVirtualAddress(
    uint64_t virtual_addr)
    : value(virtual_addr) {
  for (size_t level = 0; level < kNumLevels; ++level) {
    VirtualAddress va_bit_struct(virtual_addr);

    // Save the index into the corresponding page at `level`.
    entry_index[level] = va_bit_struct.table_index_l(level);

    // Save the starting address of the corresponding virtual address interval
    // containing `virtual_addr` at this level.
    va_bit_struct.set_physical_address_lsbs(0);
    for (size_t l = level; l < kNumLevels; ++l) {
      va_bit_struct.set_table_index_l(l, 0);
    }
    starting_interval[level] = va_bit_struct.GetEncodedValue();
  }
}

template <typename arch>
absl::Status PageTableCreator<arch>::CheckAlignmentAndSize(
    uint64_t value, absl::string_view descriptor) {
  if ((value >> kAddressWidthBits) != 0) {
    return absl::InvalidArgumentError(
        absl::StrFormat("%s does not fit within a 48-bit address space: 0x%x",
                        descriptor, value));
  }
  if ((value % PageTableCreator<arch>::kTranslationGranule) != 0) {
    return absl::InvalidArgumentError(absl::StrFormat(
        "%s should be aligned to the translation granule (4KiB) but was 0x%x",
        descriptor, value));
  }
  return absl::OkStatus();
}

template <typename arch>
size_t PageTableCreator<arch>::GetPageTableEntryIndex(
    DecodedVirtualAddress decoded_va, size_t level) {
  size_t starting_interval = decoded_va.starting_interval[level];
  size_t entry_index = decoded_va.entry_index[level];

  // If the requested entry doesn't exist, create it.
  auto entries_index = page_tables_[level].find(starting_interval);
  if (entries_index == page_tables_[level].end()) {
    page_tables_[level][starting_interval] = entries_.size();
    entries_.resize(entries_.size() + (kTranslationGranule / sizeof(uint64_t)));
    entries_index = page_tables_[level].find(starting_interval);
  }
  size_t return_value = entries_index->second + entry_index;
  DCHECK(return_value < entries_.size());
  return return_value;
}

template <typename arch>
absl::Status PageTableCreator<arch>::SetupPageDescriptor(
    DecodedVirtualAddress decoded_va, PhysicalAddress decoded_pa,
    bool writeable, bool executable) {
  size_t entry_index = GetPageTableEntryIndex(decoded_va, /*level=*/3);
  uint64_t existing_entry = entries_[entry_index];
  ASSIGN_OR_RETURN_IF_NOT_OK_PLUS(
      uint64_t new_entry,
      CreatePageDescriptor<arch>(existing_entry, decoded_pa, writeable,
                                 executable),
      absl::StrFormat("Failed to map virtual_address=0x%x", decoded_va.value));
  entries_[entry_index] = new_entry;
  return absl::OkStatus();
}

template <typename arch>
void PageTableCreator<arch>::SetupTableDescriptor(
    size_t level, DecodedVirtualAddress decoded_va, bool writeable,
    bool executable) {
  size_t entry_index = GetPageTableEntryIndex(decoded_va, level);
  uint64_t existing_entry = entries_[entry_index];

  // Calculate next table physical address.
  uint64_t next_table_starting_interval =
      decoded_va.starting_interval[level + 1];
  uint64_t next_table_entries_index =
      page_tables_[level + 1][next_table_starting_interval];
  PhysicalAddress next_table_pa(next_table_entries_index * sizeof(uint64_t) +
                                page_table_addr_);
  uint64_t modified_entry = UpdateTableDescriptor<arch>(
      existing_entry, next_table_pa, writeable, executable);

  // If the entry has not changed, we don't need to setup the lower level page
  // tables (as they should also be unchanged for this mapping).
  if (existing_entry == modified_entry) {
    return;
  }
  entries_[entry_index] = modified_entry;
  if (level > 0) {
    return SetupTableDescriptor(level - 1, decoded_va, writeable, executable);
  }
}

template class PageTableCreator<AArch64>;

template class PageTableCreator<X86_64>;

}  // namespace silifuzz::proxies
