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

#include "./proxies/page_table/page_table_entry_util.h"

#include <stddef.h>
#include <stdint.h>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_format.h"
#include "./proxies/page_table/aarch64/page_descriptor_entry.h"
#include "./proxies/page_table/aarch64/table_descriptor_entry.h"
#include "./proxies/page_table/physical_address.h"
#include "./util/arch.h"

namespace silifuzz::proxies {

template <>
absl::StatusOr<uint64_t> CreatePageDescriptor<AArch64>(
    uint64_t existing_entry, PhysicalAddress decoded_pa, bool writeable,
    bool executable) {
  // We use a new PageDescriptorEntry here so that it is properly populated with
  // default values (rather than starting as 0).
  PageDescriptorEntry<AArch64> new_descriptor;
  new_descriptor.set_valid(true);
  new_descriptor.set_output_address(decoded_pa.physical_address_msbs());
  if (writeable) {
    new_descriptor.set_ap_table_write_access(
        PageDescriptorEntry<AArch64>::kApTableWriteAccessReadWrite);
  }
  if (executable) {
    new_descriptor.set_uxn(PageDescriptorEntry<AArch64>::kUxnNoEffect);
  }

  // Check that there is no conflict with the existing page descriptor entry.
  PageDescriptorEntry<AArch64> existing_descriptor(existing_entry);
  if (existing_descriptor.valid() &&
      existing_entry != *new_descriptor.GetEncodedValue()) {
    PhysicalAddress decoded_existing_pa;
    decoded_existing_pa.set_physical_address_msbs(
        existing_descriptor.output_address());
    return absl::AlreadyExistsError(absl::StrFormat(
        "Mapping already exists with existing physical_addr=0x%x",
        *decoded_existing_pa.GetEncodedValue()));
  }

  return *new_descriptor.GetEncodedValue();
}

template <>
uint64_t UpdateTableDescriptor<AArch64>(uint64_t existing_entry,
                                        PhysicalAddress next_table_pa,
                                        bool writeable, bool executable) {
  TableDescriptorEntry<AArch64> existing_descriptor(existing_entry);
  if (!existing_descriptor.valid()) {
    // We use a new TableDescriptorEntry here so that it is properly populated
    // with default values (rather than starting as 0).
    TableDescriptorEntry<AArch64> new_descriptor;
    new_descriptor.set_valid(true);
    new_descriptor.set_next_table_address(
        next_table_pa.physical_address_msbs());
    existing_descriptor = new_descriptor;
  }

  // Update to the most permissive version of writeable/executable of all the
  // mappings related to this page.
  if (writeable) {
    existing_descriptor.set_ap_table_write_access(
        TableDescriptorEntry<AArch64>::kApTableWriteAccessReadWrite);
  }
  if (executable) {
    existing_descriptor.set_uxn_table(
        TableDescriptorEntry<AArch64>::kUxnTableNoEffect);
  }
  return *existing_descriptor.GetEncodedValue();
}

template <>
absl::StatusOr<uint64_t> CheckPageDescriptor<AArch64>(uint64_t entry,
                                                      bool writeable,
                                                      bool executable) {
  PageDescriptorEntry<AArch64> descriptor(entry);
  if (!descriptor.valid()) {
    return absl::InvalidArgumentError("Page descriptor entry is invalid.");
  }
  if (descriptor.type() != PageDescriptorEntry<AArch64>::kTypePage) {
    return absl::InvalidArgumentError("Descriptor entry is not for type page.");
  }
  if (descriptor.ap_table_unprivileged_access() !=
      PageDescriptorEntry<AArch64>::kApTableUnprivilegedAccessPermitted) {
    return absl::InvalidArgumentError(
        "Page descriptor entry does not permit unprivileged access.");
  }
  if (descriptor.pxn() != PageDescriptorEntry<AArch64>::kPxnNoEffect) {
    return absl::InvalidArgumentError(
        "Page descriptor entry has effect for pxn table.");
  }
  if (writeable &&
      descriptor.ap_table_write_access() !=
          PageDescriptorEntry<AArch64>::kApTableWriteAccessReadWrite) {
    return absl::InvalidArgumentError(
        "Page descriptor entry is not writeable.");
  }
  if (executable &&
      descriptor.uxn() != PageDescriptorEntry<AArch64>::kUxnNoEffect) {
    return absl::InvalidArgumentError(
        "Page descriptor entry is not executable.");
  }
  return descriptor.output_address();
}

template <>
absl::StatusOr<uint64_t> CheckTableDescriptor<AArch64>(uint64_t entry,
                                                       bool writeable,
                                                       bool executable) {
  TableDescriptorEntry<AArch64> descriptor(entry);
  if (!descriptor.valid()) {
    return absl::InvalidArgumentError("Table descriptor entry is invalid.");
  }
  if (descriptor.type() != TableDescriptorEntry<AArch64>::kTypeTable) {
    return absl::InvalidArgumentError(
        "Descriptor entry is not for type table.");
  }
  if (descriptor.pxn_table() !=
      TableDescriptorEntry<AArch64>::kPxnTableNoEffect) {
    return absl::InvalidArgumentError(
        "Table descriptor entry has effect for pxn table.");
  }
  if (descriptor.ap_table_unprivileged_access() !=
      TableDescriptorEntry<AArch64>::kApTableUnprivilegedAccessPermitted) {
    return absl::InvalidArgumentError(
        "Table descriptor entry does not permit unprivileged access.");
  }
  if (writeable &&
      descriptor.ap_table_write_access() !=
          TableDescriptorEntry<AArch64>::kApTableWriteAccessReadWrite) {
    return absl::InvalidArgumentError(
        "Table descriptor entry is not writeable.");
  }
  if (executable && descriptor.uxn_table() !=
                        TableDescriptorEntry<AArch64>::kUxnTableNoEffect) {
    return absl::InvalidArgumentError(
        "Table descriptor entry is not executable.");
  }
  return descriptor.next_table_address();
}

}  // namespace silifuzz::proxies
