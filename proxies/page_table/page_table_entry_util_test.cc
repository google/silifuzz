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

#include <cstdint>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "./proxies/page_table/physical_address.h"
#include "./util/arch.h"
#include "./util/testing/status_macros.h"
#include "./util/testing/status_matchers.h"

namespace silifuzz::proxies {
namespace {

using ::silifuzz::testing::StatusIs;

template <typename arch>
class PageTableEntryUtilTest : public ::testing::Test {};

TYPED_TEST_SUITE_P(PageTableEntryUtilTest);

TYPED_TEST_P(PageTableEntryUtilTest, CreateAndCheckPageDescriptor) {
  constexpr uint64_t kUnused = 0;
  constexpr bool kWriteable = true;
  constexpr bool kExecutable = true;
  PhysicalAddress expected_pa;
  expected_pa.set_physical_address_msbs(0xfeedface);

  ASSERT_OK_AND_ASSIGN(uint64_t page_descriptor,
                       CreatePageDescriptor<TypeParam>(
                           kUnused, expected_pa, kWriteable, kExecutable));
  ASSERT_OK_AND_ASSIGN(
      uint64_t output_addr,
      CheckPageDescriptor<TypeParam>(page_descriptor, kWriteable, kExecutable));
  PhysicalAddress actual_pa;
  actual_pa.set_physical_address_msbs(output_addr);
  EXPECT_EQ(expected_pa.GetEncodedValue(), actual_pa.GetEncodedValue());
}

TYPED_TEST_P(PageTableEntryUtilTest, CreateSamePageDescriptor) {
  constexpr uint64_t kUnused = 0;
  constexpr bool kWriteable = true;
  constexpr bool kExecutable = true;
  PhysicalAddress expected_pa;
  expected_pa.set_physical_address_msbs(0xfeedface);

  ASSERT_OK_AND_ASSIGN(uint64_t page_descriptor,
                       CreatePageDescriptor<TypeParam>(
                           kUnused, expected_pa, kWriteable, kExecutable));
  ASSERT_OK_AND_ASSIGN(
      uint64_t same_page_descriptor,
      CreatePageDescriptor<TypeParam>(page_descriptor, expected_pa, kWriteable,
                                      kExecutable));
  EXPECT_EQ(page_descriptor, same_page_descriptor);
}

TYPED_TEST_P(PageTableEntryUtilTest, ConflictingAddressPageDescriptorFails) {
  constexpr uint64_t kUnused = 0;
  constexpr bool kWriteable = true;
  constexpr bool kExecutable = true;
  PhysicalAddress original_pa;
  original_pa.set_physical_address_msbs(0xfeedface);
  PhysicalAddress conflicting_pa;
  conflicting_pa.set_physical_address_msbs(0xcafef00d);

  ASSERT_OK_AND_ASSIGN(uint64_t original_descriptor,
                       CreatePageDescriptor<TypeParam>(
                           kUnused, original_pa, kWriteable, kExecutable));
  EXPECT_THAT(CreatePageDescriptor<TypeParam>(
                  original_descriptor, conflicting_pa, kWriteable, kExecutable),
              StatusIs(absl::StatusCode::kAlreadyExists));
}

TYPED_TEST_P(PageTableEntryUtilTest,
             ConflictingPermissionsPageDescriptorFails) {
  constexpr uint64_t kUnused = 0;
  constexpr bool kWriteable = true;
  constexpr bool kExecutable = true;
  PhysicalAddress pa;
  pa.set_physical_address_msbs(0xfeedface);

  ASSERT_OK_AND_ASSIGN(
      uint64_t original_descriptor,
      CreatePageDescriptor<TypeParam>(kUnused, pa, kWriteable, kExecutable));
  EXPECT_THAT(CreatePageDescriptor<TypeParam>(original_descriptor, pa,
                                              !kWriteable, kExecutable),
              StatusIs(absl::StatusCode::kAlreadyExists));
  EXPECT_THAT(CreatePageDescriptor<TypeParam>(original_descriptor, pa,
                                              kWriteable, !kExecutable),
              StatusIs(absl::StatusCode::kAlreadyExists));
}

TYPED_TEST_P(PageTableEntryUtilTest, CreateAndCheckTableDescriptor) {
  constexpr uint64_t kUnused = 0;
  constexpr bool kWriteable = true;
  constexpr bool kExecutable = true;
  PhysicalAddress expected_next_table_pa;
  expected_next_table_pa.set_physical_address_msbs(0xfeedface);

  uint64_t table_descriptor = UpdateTableDescriptor<TypeParam>(
      kUnused, expected_next_table_pa, kWriteable, kExecutable);
  ASSERT_OK_AND_ASSIGN(uint64_t output_addr,
                       CheckTableDescriptor<TypeParam>(
                           table_descriptor, kWriteable, kExecutable));
  PhysicalAddress actual_next_table_pa;
  actual_next_table_pa.set_physical_address_msbs(output_addr);
  EXPECT_EQ(expected_next_table_pa.GetEncodedValue(),
            actual_next_table_pa.GetEncodedValue());
}

TYPED_TEST_P(PageTableEntryUtilTest,
             ConflictingPermissionsTableDescriptorCausesUpdate) {
  constexpr uint64_t kUnused = 0;
  PhysicalAddress next_table_pa;
  next_table_pa.set_physical_address_msbs(0xfeedface);

  uint64_t read_only_descriptor =
      UpdateTableDescriptor<TypeParam>(kUnused, next_table_pa,
                                       /*writeable=*/false,
                                       /*executable=*/false);
  uint64_t writeable_descriptor = UpdateTableDescriptor<TypeParam>(
      read_only_descriptor, next_table_pa,
      /*writeable=*/true, /*executable=*/false);
  uint64_t writeable_executable_descriptor = UpdateTableDescriptor<TypeParam>(
      writeable_descriptor, next_table_pa,
      /*writeable=*/false, /*executable=*/true);
  uint64_t still_writeable_executable_descriptor =
      UpdateTableDescriptor<TypeParam>(
          writeable_executable_descriptor, next_table_pa,
          /*writeable=*/false, /*executable=*/false);

  EXPECT_NE(read_only_descriptor, writeable_descriptor);
  EXPECT_NE(writeable_descriptor, writeable_executable_descriptor);
  EXPECT_EQ(writeable_executable_descriptor,
            still_writeable_executable_descriptor);
  EXPECT_OK(
      CheckTableDescriptor<TypeParam>(still_writeable_executable_descriptor,
                                      /*writeable=*/true, /*executable=*/true));
}

REGISTER_TYPED_TEST_SUITE_P(PageTableEntryUtilTest,
                            CreateAndCheckPageDescriptor,
                            CreateSamePageDescriptor,
                            ConflictingAddressPageDescriptorFails,
                            ConflictingPermissionsPageDescriptorFails,
                            CreateAndCheckTableDescriptor,
                            ConflictingPermissionsTableDescriptorCausesUpdate);

INSTANTIATE_TYPED_TEST_SUITE_P(AArch64PageTableEntryUtilTest,
                               PageTableEntryUtilTest, AArch64);

INSTANTIATE_TYPED_TEST_SUITE_P(X86_64PageTableEntryUtilTest,
                               PageTableEntryUtilTest, X86_64);

}  // namespace
}  // namespace silifuzz::proxies
