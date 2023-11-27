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

#ifndef THIRD_PARTY_SILIFUZZ_PROXIES_PAGE_TABLE_PAGE_TABLE_ENTRY_UTIL_H_
#define THIRD_PARTY_SILIFUZZ_PROXIES_PAGE_TABLE_PAGE_TABLE_ENTRY_UTIL_H_

#include <stddef.h>
#include <stdint.h>

#include "absl/status/statusor.h"
#include "./proxies/page_table/physical_address.h"
#include "./util/arch.h"

namespace silifuzz::proxies {

// Given the physical address that a page should point to, return the value of
// a page descriptor entry with `writeable` and `executable` attributes.
//
// Returns error if existing page descriptor entry already contains a
// conflicting mapping.
template <typename arch>
absl::StatusOr<uint64_t> CreatePageDescriptor(uint64_t existing_entry,
                                              PhysicalAddress decoded_pa,
                                              bool writeable, bool executable);

// Given the physical address for the next page table that a table entry
// should point to, create or modify the existing entry.
//
// If the table descriptor entry already exists, update the `writeable` and
// `executable` attributes of a page to be the most permissive required for
// the mappings behind it. (Note: The final page table entry will enforce the
// correct permissions per physical page. The permissions at this stage simply
// allow short-circuiting of page faults.)
template <typename arch>
uint64_t UpdateTableDescriptor(uint64_t existing_entry,
                               PhysicalAddress next_table_pa, bool writeable,
                               bool executable);

// Check that the given page descriptor entry is valid and appropriately
// `writeable` and `executable`. Return the output address that the
// descriptor points to.
template <typename arch>
absl::StatusOr<uint64_t> CheckPageDescriptor(uint64_t entry, bool writeable,
                                             bool executable);

// Check that the given table descriptor entry is valid and appropriately
// `writeable` and `executable`. Return the next table address that the
// descriptor points to.
template <typename arch>
absl::StatusOr<uint64_t> CheckTableDescriptor(uint64_t entry, bool writeable,
                                              bool executable);

// Declaractions of AArch64 specializations.
template <>
absl::StatusOr<uint64_t> CreatePageDescriptor<AArch64>(
    uint64_t existing_entry, PhysicalAddress decoded_pa, bool writeable,
    bool executable);
template <>
uint64_t UpdateTableDescriptor<AArch64>(uint64_t existing_entry,
                                        PhysicalAddress next_table_pa,
                                        bool writeable, bool executable);
template <>
absl::StatusOr<uint64_t> CheckPageDescriptor<AArch64>(uint64_t entry,
                                                      bool writeable,
                                                      bool executable);
template <>
absl::StatusOr<uint64_t> CheckTableDescriptor<AArch64>(uint64_t entry,
                                                       bool writeable,
                                                       bool executable);

}  // namespace silifuzz::proxies

#endif  // THIRD_PARTY_SILIFUZZ_PROXIES_PAGE_TABLE_PAGE_TABLE_ENTRY_UTIL_H_
