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
#include <string.h>

#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/casts.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "./common/memory_mapping.h"
#include "./common/memory_perms.h"
#include "./proxies/page_table/page_table_entry_util.h"
#include "./proxies/page_table/physical_address.h"
#include "./proxies/page_table/virtual_address.h"
#include "./util/arch.h"
#include "./util/testing/status_macros.h"
#include "./util/testing/status_matchers.h"

namespace silifuzz::proxies {
namespace {

using ::silifuzz::testing::StatusIs;
using ::testing::HasSubstr;

template <typename arch>
class PageTableCreatorTest : public ::testing::Test {
 protected:
  // Given a starting `page_table_addr`, translates the given `virtual_addr` to
  // a physical address. Checks that this result matches the provided
  // `physical_addr`. Also checks that `writeable` and `executable` are set
  // properly as it traverses the page table levels.
  static void TranslateVirtualAddress(uint64_t *page_table_addr,
                                      uint64_t virtual_addr,
                                      uint64_t physical_addr, bool writeable,
                                      bool executable) {
    VirtualAddress va(virtual_addr);
    PhysicalAddress next_table_pa;

    uint64_t *l0_entry_addr = page_table_addr + va.table_index_l0();

    ASSERT_OK_AND_ASSIGN(
        uint64_t l1_table_addr,
        CheckTableDescriptor<arch>(*l0_entry_addr, writeable, executable));
    next_table_pa.set_physical_address_msbs(l1_table_addr);
    uint64_t *l1_entry_addr =
        reinterpret_cast<uint64_t *>(*next_table_pa.GetEncodedValue()) +
        va.table_index_l1();

    ASSERT_OK_AND_ASSIGN(
        uint64_t l2_table_addr,
        CheckTableDescriptor<arch>(*l1_entry_addr, writeable, executable));
    next_table_pa.set_physical_address_msbs(l2_table_addr);
    uint64_t *l2_entry_addr =
        reinterpret_cast<uint64_t *>(*next_table_pa.GetEncodedValue()) +
        va.table_index_l2();

    ASSERT_OK_AND_ASSIGN(
        uint64_t l3_table_addr,
        CheckTableDescriptor<arch>(*l2_entry_addr, writeable, executable));
    next_table_pa.set_physical_address_msbs(l3_table_addr);
    uint64_t *l3_entry_addr =
        reinterpret_cast<uint64_t *>(*next_table_pa.GetEncodedValue()) +
        va.table_index_l3();

    ASSERT_OK_AND_ASSIGN(
        uint64_t output_addr,
        CheckPageDescriptor<arch>(*l3_entry_addr, writeable, executable));
    PhysicalAddress translated_pa;
    translated_pa.set_physical_address_lsbs(va.physical_address_lsbs());
    translated_pa.set_physical_address_msbs(output_addr);
    EXPECT_EQ(physical_addr, *translated_pa.GetEncodedValue());
  }
};

TYPED_TEST_SUITE_P(PageTableCreatorTest);

TYPED_TEST_P(PageTableCreatorTest, UnalignedPageTableAddress) {
  ASSERT_DEATH({ PageTableCreator<TypeParam> creator(/*page_table_addr=*/10); },
               "page_table_addr");
}

TYPED_TEST_P(PageTableCreatorTest, UnalignedArguments) {
  constexpr uint64_t kValid = 0x4000;
  constexpr uint64_t kInvalid = 0x20;

  PageTableCreator<TypeParam> creator(/*page_table_addr=*/0);
  ASSERT_THAT(
      creator.AddContiguousMapping(
          MemoryMapping::MakeSized(/*start_address=*/kInvalid,
                                   /*num_bytes=*/kValid, MemoryPerms::R()),
          /*physical_addr=*/kValid),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("virtual_addr")));
  ASSERT_THAT(
      creator.AddContiguousMapping(
          MemoryMapping::MakeSized(/*start_address=*/kValid,
                                   /*num_bytes=*/kValid, MemoryPerms::R()),
          /*physical_addr=*/kInvalid),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("physical_addr")));
  ASSERT_THAT(creator.AddContiguousMapping(
                  MemoryMapping::MakeSized(
                      /*start_address=*/kValid,
                      /*num_bytes=*/kInvalid, MemoryPerms::R()),
                  /*physical_addr=*/kValid),
              StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("size")));
}

TYPED_TEST_P(PageTableCreatorTest, TooLargeArguments) {
  constexpr uint64_t kValid = 0x4000;
  // Invalid because it does not fit within 48-bit address space.
  constexpr uint64_t kInvalid = 0x1'0000'0000'0000;

  PageTableCreator<TypeParam> creator(/*page_table_addr=*/0);
  ASSERT_THAT(
      creator.AddContiguousMapping(MemoryMapping::MakeSized(
                                       /*start_address=*/kInvalid,
                                       /*num_bytes=*/kValid, MemoryPerms::R()),
                                   /*physical_addr=*/kValid),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("starting virtual_addr")));
  ASSERT_THAT(
      creator.AddContiguousMapping(
          MemoryMapping::MakeSized(/*start_address=*/kValid,
                                   /*num_bytes=*/kValid, MemoryPerms::R()),
          /*physical_addr=*/kInvalid),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("starting physical_addr")));
  ASSERT_THAT(creator.AddContiguousMapping(
                  MemoryMapping::MakeSized(
                      /*start_address=*/kValid,
                      /*num_bytes=*/kInvalid, MemoryPerms::R()),
                  /*physical_addr=*/kValid),
              StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("size")));
}

TYPED_TEST_P(PageTableCreatorTest, MappingEndsOutsideOfRange) {
  constexpr uint64_t kSmallAddress = 0x1'0000;
  constexpr uint64_t kLargeAddress = 0xFFFF'FFFF'0000;
  constexpr uint64_t kValidSize = 0x1'1000;

  PageTableCreator<TypeParam> creator(/*page_table_addr=*/0);
  ASSERT_THAT(creator.AddContiguousMapping(
                  MemoryMapping::MakeSized(
                      /*start_address=*/kLargeAddress,
                      /*num_bytes=*/kValidSize, MemoryPerms::R()),
                  /*physical_addr=*/kSmallAddress),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("ending virtual_addr")));
  ASSERT_THAT(
      creator.AddContiguousMapping(
          MemoryMapping::MakeSized(/*start_address=*/kSmallAddress,
                                   /*num_bytes=*/kValidSize, MemoryPerms::R()),
          /*physical_addr=*/kLargeAddress),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("ending physical_addr")));
}

TYPED_TEST_P(PageTableCreatorTest, ConflictingMappingsDifferentAddresses) {
  constexpr uint64_t kVirtualAddr = 0x20000;
  constexpr size_t kSize = 0x4000;

  PageTableCreator<TypeParam> creator(/*page_table_addr=*/0);
  ASSERT_OK(creator.AddContiguousMapping(
      MemoryMapping::MakeSized(kVirtualAddr, kSize, MemoryPerms::R()),
      /*physical_addr=*/0x1000));

  // A virtual address cannot translate to two different physical addresses.
  ASSERT_THAT(
      creator.AddContiguousMapping(
          MemoryMapping::MakeSized(kVirtualAddr, kSize, MemoryPerms::R()),
          /*physical_addr=*/0x8000),
      StatusIs(absl::StatusCode::kAlreadyExists));

  // Checks that overlaps are also not allowed.
  ASSERT_THAT(creator.AddContiguousMapping(
                  MemoryMapping::MakeSized(kVirtualAddr + 0x1000, kSize,
                                           MemoryPerms::R()),
                  /*physical_addr=*/0x8000),
              StatusIs(absl::StatusCode::kAlreadyExists));
}

TYPED_TEST_P(PageTableCreatorTest, ConflictingMappingsDifferentPermissions) {
  constexpr uint64_t kVirtualAddr = 0x20000;
  constexpr uint64_t kPhysicalAddr = 0x1000;
  constexpr size_t kSize = 0x4000;

  PageTableCreator<TypeParam> creator(/*page_table_addr=*/0);
  ASSERT_OK(creator.AddContiguousMapping(
      MemoryMapping::MakeSized(kVirtualAddr, kSize, MemoryPerms::XR()),
      kPhysicalAddr));

  ASSERT_THAT(
      creator.AddContiguousMapping(
          MemoryMapping::MakeSized(kVirtualAddr, kSize, MemoryPerms::RWX()),
          kPhysicalAddr),
      StatusIs(absl::StatusCode::kAlreadyExists));

  ASSERT_THAT(
      creator.AddContiguousMapping(
          MemoryMapping::MakeSized(kVirtualAddr, kSize, MemoryPerms::R()),
          kPhysicalAddr),
      StatusIs(absl::StatusCode::kAlreadyExists));
}

TYPED_TEST_P(PageTableCreatorTest, MappingsMatchingExistingMappingsIgnored) {
  constexpr uint64_t kVirtualAddr = 0x20000;
  constexpr uint64_t kPhysicalAddr = 0x1000;
  constexpr size_t kSize = 0x4000;

  PageTableCreator<TypeParam> creator(/*page_table_addr=*/0);
  ASSERT_OK(creator.AddContiguousMapping(
      MemoryMapping::MakeSized(kVirtualAddr, kSize, MemoryPerms::XR()),
      kPhysicalAddr));

  // New mappings that match old mappings are not rejected.
  ASSERT_OK(creator.AddContiguousMapping(
      MemoryMapping::MakeSized(kVirtualAddr, kSize * 2, MemoryPerms::XR()),
      kPhysicalAddr));
}

TYPED_TEST_P(PageTableCreatorTest, OnlyInsertPagesWhenNeeded) {
  constexpr uint64_t kVirtualAddr = 0x20000;
  constexpr uint64_t kPhysicalAddr = 0x1000;
  constexpr size_t kSize = 0x4000;

  // Create a mapping that should fit in 1 page per level.
  PageTableCreator<TypeParam> creator(/*page_table_addr=*/0);
  ASSERT_OK(creator.AddContiguousMapping(
      MemoryMapping::MakeSized(kVirtualAddr, kSize, MemoryPerms::R()),
      kPhysicalAddr));
  // Note: We make a copy here as the vector will be changing with the next
  // mapping.
  const std::vector<uint64_t> bits1 = creator.GetBinaryData();
  uint64_t size_in_bytes1 = bits1.size() * sizeof(uint64_t);
  EXPECT_EQ(size_in_bytes1, creator.kTranslationGranule * 4);

  // Add a mapping that should modify the same pages that already exist. Size of
  // bit representation should not change, but the representations will differ.
  ASSERT_OK(creator.AddContiguousMapping(
      MemoryMapping::MakeSized(kVirtualAddr + kSize, kSize, MemoryPerms::R()),
      kPhysicalAddr + kSize));
  const std::vector<uint64_t> &bits2 = creator.GetBinaryData();
  uint64_t size_in_bytes2 = bits2.size() * sizeof(uint64_t);
  EXPECT_EQ(size_in_bytes2, creator.kTranslationGranule * 4);
  EXPECT_EQ(size_in_bytes1, size_in_bytes2);
  EXPECT_NE(bits1, bits2);
}

TYPED_TEST_P(PageTableCreatorTest, MakeMappings) {
  // Set aside space to copy the page table to.
  // Note: Page table must be 4KiB-aligned in order to use the address directly.
  constexpr uint64_t kPageSizeInUint64s =
      PageTableCreator<TypeParam>::kTranslationGranule / sizeof(uint64_t);
  alignas(PageTableCreator<TypeParam>::kTranslationGranule)
      uint64_t page_table[kPageSizeInUint64s * 6];
  PageTableCreator<TypeParam> creator(
      /*page_table_addr=*/absl::bit_cast<uint64_t>(&page_table));

  // Add two mappings to fill up 6 pages of the page table: 1 page in L0/L1, 2
  // pages in L2/L3.
  constexpr uint64_t kVirtualAddr1 = 0x2'0000;
  constexpr uint64_t kPhysicalAddr1 = 0x1000;
  constexpr size_t kSize1 = 0x4000;
  ASSERT_OK(creator.AddContiguousMapping(
      MemoryMapping::MakeSized(kVirtualAddr1, kSize1, MemoryPerms::XR()),
      kPhysicalAddr1));

  constexpr uint64_t kVirtualAddr2 = 0x1'0F87'0000;
  constexpr uint64_t kPhysicalAddr2 = 0x8000;
  constexpr size_t kSize2 = 0x1000;
  ASSERT_OK(creator.AddContiguousMapping(
      MemoryMapping::MakeSized(kVirtualAddr2, kSize2, MemoryPerms::RW()),
      kPhysicalAddr2));

  const std::vector<uint64_t> bits = creator.GetBinaryData();
  EXPECT_EQ(bits.size() * sizeof(uint64_t), sizeof(page_table));
  memcpy(&page_table, bits.data(), bits.size() * sizeof(uint64_t));

  // Check that the two mappings were setup properly by translating different
  // addresses.
  ASSERT_NO_FATAL_FAILURE(
      this->TranslateVirtualAddress(page_table, kVirtualAddr1, kPhysicalAddr1,
                                    /*writeable=*/false, /*executable=*/true));
  ASSERT_NO_FATAL_FAILURE(this->TranslateVirtualAddress(
      page_table, kVirtualAddr1 + 0x2222, kPhysicalAddr1 + 0x2222,
      /*writeable=*/false, /*executable=*/true));
  ASSERT_NO_FATAL_FAILURE(
      this->TranslateVirtualAddress(page_table, kVirtualAddr2, kPhysicalAddr2,
                                    /*writeable=*/true, /*executable=*/false));
  ASSERT_NO_FATAL_FAILURE(this->TranslateVirtualAddress(
      page_table, kVirtualAddr2 + 0xFFF, kPhysicalAddr2 + 0xFFF,
      /*writeable=*/true, /*executable=*/false));
}

REGISTER_TYPED_TEST_SUITE_P(PageTableCreatorTest, UnalignedPageTableAddress,
                            UnalignedArguments, TooLargeArguments,
                            MappingEndsOutsideOfRange,
                            ConflictingMappingsDifferentAddresses,
                            ConflictingMappingsDifferentPermissions,
                            MappingsMatchingExistingMappingsIgnored,
                            OnlyInsertPagesWhenNeeded, MakeMappings);

INSTANTIATE_TYPED_TEST_SUITE_P(AArch64PageTableCreatorTest,
                               PageTableCreatorTest, AArch64);

}  // namespace
}  // namespace silifuzz::proxies
