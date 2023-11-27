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

#ifndef THIRD_PARTY_SILIFUZZ_PROXIES_PAGE_TABLE_AARCH64_PAGE_DESCRIPTOR_ENTRY_H_
#define THIRD_PARTY_SILIFUZZ_PROXIES_PAGE_TABLE_AARCH64_PAGE_DESCRIPTOR_ENTRY_H_

#include <cstdint>

#include "./proxies/page_table/bit_struct.h"
#include "./util/arch.h"

namespace silifuzz::proxies {

// Represents a page table entry intended to describe a physical page for
// 'arch'.
template <typename arch>
class PageDescriptorEntry;

// Represents a page table entry intended to describe a physical page for
// AArch64'. This entry is a translation setup with 4KB translation granules and
// 48-bit physical addresses for a stage 1 translation. Reference: ARM
// Architecture Reference Manual, Figure D8-15
//
// Note: One-stage translation indicates that the input virtual address is being
// translated to a physical output address. Two-stage translation indicates that
// the input virtual address is being translated to an IPA (intermediate
// physical address), which is then translated to the physical address.
// Reference: ARM Architecture Reference Manual, Page D8-5080
template <>
class PageDescriptorEntry<AArch64> : public BitStruct {
 public:
  // Value encodings for fields.
  enum access_flag_value {
    kAccessFlagNotAccessed = 0,
    kAccessFlagAccessed = 1
  };

  enum ap_table_unprivileged_access_value {
    kApTableUnprivilegedAccessNotPermitted = 0,
    kApTableUnprivilegedAccessPermitted = 1
  };

  enum ap_table_write_access_value {
    kApTableWriteAccessReadWrite = 0,
    kApTableWriteAccessReadOnly = 1
  };

  enum non_secure_value {
    kNonSecureSecurePaSpace = 0,
    kNonSecureNonSecurePaSpace = 1
  };

  enum pxn_value { kPxnNoEffect = 0, kPxnPrivilegedExecuteNever = 1 };

  enum shareability_value {
    kShareabilityNonShareable = 0,
    kShareabilityReserved = 1,
    kShareabilityOuterShareable = 2,
    kShareabilityInnerShareable = 3
  };

  enum type_value { kTypeReserved = 0, kTypePage = 1 };

  enum uxn_value { kUxnNoEffect = 0, kUxnUnprivilegedExecuteNever = 1 };

  explicit constexpr PageDescriptorEntry(uint64_t bits) : BitStruct(bits) {}
  ~PageDescriptorEntry() = default;

  // Copyable and movable by default.
  PageDescriptorEntry(const PageDescriptorEntry&) = default;
  PageDescriptorEntry& operator=(const PageDescriptorEntry&) = default;
  PageDescriptorEntry(PageDescriptorEntry&&) = default;
  PageDescriptorEntry& operator=(PageDescriptorEntry&&) = default;

  // Bit fields in PageDescriptorEntry:
  //
  // Indicates whether the page table entry is valid.
  // Reference: ARM Cortex-A Series Programmer's Guide for ARMv8-A, Fig 12-10
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(valid, 0, 0)

  // Indicates that the page table entry is a page descriptor entry.
  // Note: We initialize this to 0x1 (page) for this bit struct description.
  // Reference: ARM Cortex-A Series Programmer's Guide for ARMv8-A, Fig 12-10
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(type, 1, 1)

  // Specified stage 1 memory attributes index field for the MAIR_ELx register.
  // Reference: ARM Architecture Reference Manual, Section D8.5.1, Page D8-5151
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(attr_index, 2, 4)

  // When access is from Secure state, indicates whether an access to the
  // output address specified by the descriptor is to non-secure or secure
  // physical address space.
  // Reference: ARM Architecture Reference Manual, Page D8-5135
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(non_secure, 5, 5)

  // Translation table entries at a given lookup level can limit data access
  // permissions at subsequent lookup levels.
  // Reference: ARM Architecture Reference Manual, Table D8-39, Section D8.4.3
  // Note: This enum is backwards of the same enum in table descriptor entries.
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(ap_table_unprivileged_access, 6, 6)

  // Translation table entries at a given lookup level can limit data access
  // permissions at subsequent lookup levels.
  // Reference: ARM Architecture Reference Manual, Table D8-41, Section D8.4.3
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(ap_table_write_access, 7, 7)

  // Shareability attributes define the data coherency requirements of a
  // location, which hardware must enforce. An Inner Shareability domain is a
  // subset of a single Outer Shareability domain.
  // Reference: ARM Architecture Reference Manual, Page D8-5152
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(shareability, 8, 9)

  // Indicates whether the memory region has been accessed since the AF
  // (access flag) was last set to 0. Descriptors with AF set to zero can
  // never be cached in a TLB.
  // Reference: ARM Architecture Reference Manual, Page D8-5143
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(access_flag, 10, 10)

  // Only meaningful for stage 1 translations that support two privilege
  // levels. ARM expects that software configures translations specific to a
  // process to be associated with a specific ASID (address space identifier).
  // A TLB entry associated with a specific ASID can only be used to translate
  // a virtual address in a context associated with the matching ASID.
  // The ASID permits software to switch between process-specific translation
  // table mappings without removing previous mapping cached for another ASID
  // from a TLB. A set nG (non-global) bit in any level of the translation
  // table walk will result in the translation being treated as non-global.
  // Reference: ARM Architecture Reference Manual, Page D8-5194
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(not_global, 11, 11)

  // Upper 36 bits of the output address. The lower 12 bits (that specify the
  // offset within the translation granule) are taken directly from the input
  // (virtual) address.
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(output_address, 12, 47)

  // Reserved
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(res0, 48, 49)

  // Only relevant if FEAT_BTI is implemented. Indicates that this page is a
  // guarded page.
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(guarded_page, 50, 50)

  // Only relevant if FEAT_HAFDBS is implemented. Indicates that a memory
  // block or page has been modified and whether this page descriptor is a
  // candidate for hardware updates of the dirty state.
  // Reference: ARM Architecture Reference Manual, Page D8-5145
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(dirty, 51, 51)

  // Directs the TLB (translation lookup buffer) to cache this entry as
  // belonging to a group of adjacent translation table entries that point to
  // a contiguous output address range.
  // Reference: ARM Architecture Reference Manual, Page D8-5158
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(contiguous, 52, 52)

  // Only meaningful for stage 1 translations in secure state.
  // For stage 1 translations that support two privilege levels, sets the
  // privileged execute-never field.
  // Reference: ARM Architecture Reference Manual, Page D8-5129
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(pxn, 53, 53)

  // For stage 1 translations that support two privilege levels, sets the
  // unprivileged execute-never field for EL0.
  // Reference: ARM Architecture Reference Manual, Page D8-5128
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(uxn, 54, 54)

  // Ignored; reserved for software use
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(ignored0, 55, 58)

  // Page-Based Hardware Attributes bits: Only meaningful if FEAT_HPDS2 is
  // implemented.
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(pbha, 59, 62)

  // Ignored for stage 1 translations
  SILIFUZZ_PROXY_BIT_STRUCT_FIELD(ignored1, 63, 63)

  // Default constructor has to be defined after field declarations.
  constexpr PageDescriptorEntry() : BitStruct() {
    set_type(kTypePage)
        .set_non_secure(kNonSecureNonSecurePaSpace)
        .set_ap_table_unprivileged_access(kApTableUnprivilegedAccessPermitted)
        .set_ap_table_write_access(kApTableWriteAccessReadOnly)
        .set_not_global(0)
        .set_pxn(kPxnNoEffect)
        .set_uxn(kUxnUnprivilegedExecuteNever);
  }
};

}  // namespace silifuzz::proxies

#endif  // THIRD_PARTY_SILIFUZZ_PROXIES_PAGE_TABLE_AARCH64_PAGE_DESCRIPTOR_ENTRY_H_
