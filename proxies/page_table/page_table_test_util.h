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

#ifndef THIRD_PARTY_SILIFUZZ_PROXIES_PAGE_TABLE_PAGE_TABLE_TEST_UTIL_H_
#define THIRD_PARTY_SILIFUZZ_PROXIES_PAGE_TABLE_PAGE_TABLE_TEST_UTIL_H_

#include <cstdint>

#include "absl/status/statusor.h"
#include "./proxies/page_table/page_table_entry_util.h"
#include "./proxies/page_table/physical_address.h"
#include "./proxies/page_table/virtual_address.h"
#include "./util/checks.h"

namespace silifuzz::proxies {

// Helpers for page table unit tests.

// Given a starting `page_table_addr`, translates the given `virtual_addr` to
// a physical address. Returns the physical address. Also checks that
// `writeable` and `executable` are set properly as it traverses the page
// table levels.
template <typename arch>
absl::StatusOr<uint64_t> TranslateVirtualAddress(uint64_t *page_table_addr,
                                                 uint64_t virtual_addr,
                                                 bool writeable,
                                                 bool executable) {
  VirtualAddress va(virtual_addr);
  PhysicalAddress next_table_pa;

  uint64_t *l0_entry_addr = page_table_addr + va.table_index_l0();
  ASSIGN_OR_RETURN_IF_NOT_OK(
      uint64_t l1_table_addr,
      CheckTableDescriptor<arch>(*l0_entry_addr, writeable, executable));
  next_table_pa.set_physical_address_msbs(l1_table_addr);
  uint64_t *l1_entry_addr =
      reinterpret_cast<uint64_t *>(next_table_pa.GetEncodedValue()) +
      va.table_index_l1();

  ASSIGN_OR_RETURN_IF_NOT_OK(
      uint64_t l2_table_addr,
      CheckTableDescriptor<arch>(*l1_entry_addr, writeable, executable));
  next_table_pa.set_physical_address_msbs(l2_table_addr);
  uint64_t *l2_entry_addr =
      reinterpret_cast<uint64_t *>(next_table_pa.GetEncodedValue()) +
      va.table_index_l2();

  ASSIGN_OR_RETURN_IF_NOT_OK(
      uint64_t l3_table_addr,
      CheckTableDescriptor<arch>(*l2_entry_addr, writeable, executable));
  next_table_pa.set_physical_address_msbs(l3_table_addr);
  uint64_t *l3_entry_addr =
      reinterpret_cast<uint64_t *>(next_table_pa.GetEncodedValue()) +
      va.table_index_l3();

  ASSIGN_OR_RETURN_IF_NOT_OK(
      uint64_t output_addr,
      CheckPageDescriptor<arch>(*l3_entry_addr, writeable, executable));
  PhysicalAddress translated_pa;
  translated_pa.set_physical_address_lsbs(va.physical_address_lsbs());
  translated_pa.set_physical_address_msbs(output_addr);
  return translated_pa.GetEncodedValue();
}

}  // namespace silifuzz::proxies

#endif  // THIRD_PARTY_SILIFUZZ_PROXIES_PAGE_TABLE_PAGE_TABLE_TEST_UTIL_H_
